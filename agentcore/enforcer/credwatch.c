//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

/* Pseudo-filesystem magics to skip — credential files never live on these.
 * tmpfs is intentionally NOT skipped: CI containers often mount tmpfs at
 * /dev/shm, /run, or /tmp, and credentials can be written there. The
 * filename pre-filter (watched_filenames map) eliminates 99%+ of the
 * bpf_d_path cost for opens on tmpfs that target non-credential files. */
#define PROC_SUPER_MAGIC      0x9fa0
#define SYSFS_MAGIC           0x62656572
#define CGROUP_SUPER_MAGIC    0x27e0eb
#define DEBUGFS_MAGIC         0x64626720
#define DEVPTS_SUPER_MAGIC    0x1cd1

/* Bit flags for cgroup_proc_config.flags */
#define FLAG_MONITORED        1
#define FLAG_ALLOW_CREDWATCH  4
/* Observe-only: emit the ringbuf event for visibility but DON'T
 * deny the open. Intended for sandboxed detonation environments
 * where killing the workload at first cred read defeats the purpose —
 * we want the sample to RUN so the full kill chain is captured, while
 * still surfacing every cred touch as an event. */
#define FLAG_OBSERVE_ONLY     8

struct cgroup_proc_config {
    __u8 flags;
} __attribute__((packed));

struct credwatch_event {
    __u64 cgroup_id;
    __u32 pid;
    char  comm[16];
    char  path[128];
    __u64 timestamp_ns;
} __attribute__((packed));

/* Cgroup IDs of monitored containers — pre-filter to skip host processes.
 * Value is cgroup_proc_config (flags byte), not a simple presence flag,
 * because we need the allow_credwatch exemption per container. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);                       /* cgroup_id */
    __type(value, struct cgroup_proc_config);
} known_containers SEC(".maps");

/* Watched filename strings — dentry name (last path component) pre-filter.
 * Populated by userspace from the filename portion of each watched suffix.
 * Keyed by null-terminated char[64]. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[64]);                    /* filename, e.g. "id_rsa" */
    __type(value, __u8);                      /* presence flag */
} watched_filenames SEC(".maps");

/* Watched path suffixes — matched against the tail of bpf_d_path output.
 * Keyed by null-terminated char[64]. Populated by userspace from config.
 * E.g. "/.ssh/id_rsa" matches /home/runner/.ssh/id_rsa,
 *                          /root/.ssh/id_rsa, etc. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[64]);                    /* suffix, e.g. "/.ssh/id_rsa" */
    __type(value, __u8);                      /* presence flag */
} watched_suffixes SEC(".maps");

/* Per-CPU scratch buffer for bpf_d_path output. Stack memory does not
 * allow variable-offset reads; per-CPU array map values do. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[128]);
} path_buf SEC(".maps");

/* Ring buffer for credential file access events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  /* 64KB */
} credwatch_events SEC(".maps");

/* Count of ringbuf reserve failures (ring full). The deny verdict does
 * not depend on the reserve, but a full ring silently loses the
 * evidence, so userspace reads this to surface the loss. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} reserve_failures SEC(".maps");

/* Force clang to emit BTF for credwatch_event. Without a live reference, the
 * ringbuf-reserve path uses void* and BTF drops the struct — which blocks
 * the userspace struct-size self-check at load time. Concrete instance
 * (not a pointer-with-used) for toolchain-stable BTF retention — see
 * egress.c __sock_owner_btf_hint comment for rationale. */
volatile const struct credwatch_event __credwatch_event_btf_hint;

/* match_suffix checks whether the resolved path ends with any watched
 * suffix. It tries every '/' position in the path as a potential suffix
 * start, builds the candidate string from there and looks it up in the
 * watched_suffixes hash map. Position 0 is included: a path such as
 * "/.ssh/id_rsa" (a process whose root is the home directory's parent,
 * or an absolute watched suffix) matches at pos 0.
 *
 * Uses constant-offset reads within each suffix to satisfy the BPF
 * verifier's variable-offset restrictions. */
static __always_inline int match_suffix(const char *path, long path_len)
{
    /* Upper bound is path_len (the string length from bpf_d_path),
     * capped at 127 to stay within the 128-byte path_buf. The verifier
     * needs a constant upper bound; path_len ≤ 128 is guaranteed by
     * the bpf_d_path(buf, 128) call, so pos < 128 is safe for reads. */
#pragma unroll
    for (int pos = 0; pos < 127; pos++) {
        /* Stop past the resolved path length */
        if (pos >= path_len)
            break;

        /* Only start a suffix match on '/' — all watched suffixes
         * begin with '/' (e.g., "/.ssh/id_rsa"). */
        if (path[pos] != '/')
            continue;

        /* Build candidate suffix from path[pos] onward into a
         * fixed-size buffer for the hash map lookup.
         * Bound j so pos+j never exceeds 126 (within the 128-byte buf). */
        char suffix[64] = {};
#pragma unroll
        for (int j = 0; j < 63; j++) {
            if (pos + j > 126)
                break;
            if (path[pos + j] == '\0')
                break;
            suffix[j] = path[pos + j];
        }

        /* Lookup in watched_suffixes map */
        __u8 *found = bpf_map_lookup_elem(&watched_suffixes, &suffix);
        if (found)
            return 1;
    }

    return 0;
}

/* read_dentry_name_of reads a dentry's filename (last path component)
 * into a fixed-size buffer for the watched_filenames pre-filter lookup.
 * Returns the length of the filename, or 0 on error. */
static __always_inline int read_dentry_name_of(struct dentry *dentry, char *name_out)
{
    struct qstr dname;
    if (bpf_core_read(&dname, sizeof(dname), &dentry->d_name))
        return 0;

    /* dname.name points at the name data; read up to 63 bytes + NUL. */
    long len = bpf_probe_read_kernel_str(name_out, 64, dname.name);
    if (len < 0)
        return 0;

    return len;
}

/* emit_credwatch publishes one event. src is copied into the 128-byte
 * path field; callers pass either the resolved path (128 bytes) or a
 * bare filename (64 bytes) — n must be a compile-time constant. */
#define EMIT_CREDWATCH(cgroup_id_, src_, n_)                                    \
    do {                                                                       \
        struct credwatch_event *_evt;                                          \
        _evt = bpf_ringbuf_reserve(&credwatch_events, sizeof(*_evt), 0);       \
        if (_evt) {                                                            \
            __builtin_memset(_evt, 0, sizeof(*_evt));                          \
            _evt->cgroup_id = (cgroup_id_);                                    \
            _evt->pid = bpf_get_current_pid_tgid() >> 32;                      \
            _evt->timestamp_ns = bpf_ktime_get_ns();                           \
            bpf_get_current_comm(&_evt->comm, sizeof(_evt->comm));             \
            __builtin_memcpy(&_evt->path, (src_), (n_));                       \
            bpf_ringbuf_submit(_evt, 0);                                       \
        } else {                                                               \
            __u32 _z = 0;                                                      \
            __u64 *_c = bpf_map_lookup_elem(&reserve_failures, &_z);           \
            if (_c)                                                            \
                *_c += 1;                                                      \
        }                                                                      \
    } while (0)

/* watched_container applies the cgroup pre-filter and the
 * allow_credwatch exemption. Returns the config for a container that
 * must be enforced, or NULL. */
static __always_inline struct cgroup_proc_config *watched_container(__u64 *cgroup_id)
{
    *cgroup_id = bpf_get_current_cgroup_id();
    struct cgroup_proc_config *cfg = bpf_map_lookup_elem(&known_containers, cgroup_id);
    if (!cfg)
        return 0;
    if (cfg->flags & FLAG_ALLOW_CREDWATCH)
        return 0;
    return cfg;
}

SEC("lsm/file_open")
int BPF_PROG(credwatch_file_open, struct file *file)
{
    /* 1+2. Cgroup pre-filter and allow_credwatch exemption */
    __u64 cgroup_id;
    struct cgroup_proc_config *cfg = watched_container(&cgroup_id);
    if (!cfg)
        return 0;

    /* 3. Skip pseudo-filesystems — credential files are on real
     * filesystems (ext4, xfs, etc.). Checking s_magic avoids the
     * cost of bpf_d_path for opens on proc, sysfs, cgroup, etc. */
    __u64 magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
    if (magic == PROC_SUPER_MAGIC || magic == SYSFS_MAGIC ||
        magic == CGROUP_SUPER_MAGIC || magic == DEBUGFS_MAGIC ||
        magic == DEVPTS_SUPER_MAGIC)
        return 0;

    /* 4. Dentry filename pre-filter — read the last path component
     * (the filename) and check against watched_filenames. This
     * avoids bpf_d_path for 99%+ of opens where the filename is
     * not a credential file name (e.g., "main.go", "output.log"). */
    char filename[64] = {};
    if (read_dentry_name_of(BPF_CORE_READ(file, f_path.dentry), filename) == 0)
        return 0;

    __u8 *fname_found = bpf_map_lookup_elem(&watched_filenames, &filename);
    if (!fname_found)
        return 0;

    /* 5. Resolve file path into per-CPU scratch buffer. The file
     * argument to lsm/file_open is a trusted pointer, so
     * &file->f_path is valid for bpf_d_path in non-sleepable
     * LSM context. */
    __u32 zero = 0;
    char *buf = bpf_map_lookup_elem(&path_buf, &zero);
    if (!buf)
        goto fail_closed;

    long path_len = bpf_d_path(&file->f_path, buf, 128);
    if (path_len < 0)
        goto fail_closed; /* e.g. ENAMETOOLONG: the path does not fit */

    /* 6. Check if path matches any watched suffix */
    if (!match_suffix(buf, path_len))
        return 0;

    /* 7. Emit event to ring buffer */
    EMIT_CREDWATCH(cgroup_id, buf, 128);
    goto verdict;

fail_closed:
    /* The watched-name prefilter matched but the full path could not be
     * resolved (path too long for the buffer, or no scratch buffer).
     * Allowing here would let a deep directory defeat the watch, so
     * treat it as a hit: report the bare filename and apply the same
     * verdict as a confirmed match. */
    EMIT_CREDWATCH(cgroup_id, filename, 64);

verdict:
    /* 8. Deny the open — unless this container is in observe-only
     * mode, in which case we've already emitted the event and let
     * the open proceed. */
    if (cfg->flags & FLAG_OBSERVE_ONLY)
        return 0;
    return -EPERM;
}

/* watched_name_verdict is shared by the path_rename and path_link hooks.
 * A credential file can be renamed or hard-linked to a name the
 * file_open prefilter does not watch (mv id_rsa x; ln id_rsa /tmp/x),
 * then opened under that name. Treat touching the source name like an
 * open of it: report and apply the same verdict. Only the source
 * dentry's name is available here, so the event path is that bare name. */
static __always_inline int watched_name_verdict(struct dentry *src)
{
    __u64 cgroup_id;
    struct cgroup_proc_config *cfg = watched_container(&cgroup_id);
    if (!cfg)
        return 0;

    char filename[64] = {};
    if (read_dentry_name_of(src, filename) == 0)
        return 0;

    __u8 *found = bpf_map_lookup_elem(&watched_filenames, &filename);
    if (!found)
        return 0;

    EMIT_CREDWATCH(cgroup_id, filename, 64);

    if (cfg->flags & FLAG_OBSERVE_ONLY)
        return 0;
    return -EPERM;
}

SEC("lsm/path_rename")
int BPF_PROG(credwatch_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
    return watched_name_verdict(old_dentry);
}

SEC("lsm/path_link")
int BPF_PROG(credwatch_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    return watched_name_verdict(old_dentry);
}

char __license[] SEC("license") = "GPL";
