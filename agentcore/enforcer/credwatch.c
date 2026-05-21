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

/* Force clang to emit BTF for credwatch_event. Without a live reference, the
 * ringbuf-reserve path uses void* and BTF drops the struct — which blocks
 * the userspace struct-size self-check at load time. */
struct credwatch_event *__credwatch_event_btf_hint __attribute__((used));

/* match_suffix checks whether the resolved path ends with any watched
 * suffix. It scans backwards from the end of the path string, trying
 * each position as a potential suffix start. For each position, it
 * constructs a candidate suffix string and looks it up in the
 * watched_suffixes hash map.
 *
 * The scan range covers suffixes up to 63 chars. Path positions 0-4
 * are skipped because credential suffixes always start with "/" and
 * need at least a few prefix chars (e.g., "/.ssh/id_rsa" at pos N-14).
 *
 * Uses constant-offset reads within each suffix to satisfy the BPF
 * verifier's variable-offset restrictions. */
static __always_inline int match_suffix(const char *path, long path_len)
{
    /* Suffixes start with '/', so the earliest possible match position
     * is 1 (a path like "/.ssh/id_rsa" would have the suffix at pos 0,
     * but most real paths have a longer prefix). Start scanning from
     * position 1 to allow short home dirs. */
    int start = path_len < 63 ? 1 : path_len - 63;
    if (start < 1)
        start = 1;

    /* Upper bound is path_len (the string length from bpf_d_path),
     * capped at 127 to stay within the 128-byte path_buf. The verifier
     * needs a constant upper bound; path_len ≤ 128 is guaranteed by
     * the bpf_d_path(buf, 128) call, so pos < 128 is safe for reads. */
#pragma unroll
    for (int pos = 1; pos < 127; pos++) {
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

/* read_dentry_name reads the dentry filename (last path component) into
 * a fixed-size buffer for the watched_filenames pre-filter lookup.
 * Returns the length of the filename, or 0 on error. */
static __always_inline int read_dentry_name(struct file *file, char *name_out)
{
    struct qstr dname;
    /* Read the dentry name qstr from file->f_path.dentry->d_name.
     * BPF_CORE_READ_INTO reads the struct in one go. */
    if (bpf_core_read(&dname, sizeof(dname), &file->f_path.dentry->d_name))
        return 0;

    /* Read the name string. dname.name is a const char* pointing to
     * the name data. We read up to 63 bytes into name_out. */
    long len = bpf_probe_read_kernel_str(name_out, 64, dname.name);
    if (len < 0)
        return 0;

    return len;
}

SEC("lsm/file_open")
int BPF_PROG(credwatch_file_open, struct file *file)
{
    /* 1. Cgroup pre-filter — skip non-container processes */
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct cgroup_proc_config *cfg = bpf_map_lookup_elem(&known_containers, &cgroup_id);
    if (!cfg)
        return 0;

    /* 2. Exempt containers with allow_credwatch label */
    if (cfg->flags & FLAG_ALLOW_CREDWATCH)
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
    if (read_dentry_name(file, filename) == 0)
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
        return 0;

    long path_len = bpf_d_path(&file->f_path, buf, 128);
    if (path_len < 0)
        return 0;

    /* 6. Check if path matches any watched suffix */
    if (!match_suffix(buf, path_len))
        return 0;

    /* 7. Emit event to ring buffer */
    struct credwatch_event *evt;
    evt = bpf_ringbuf_reserve(&credwatch_events, sizeof(*evt), 0);
    if (evt) {
        evt->cgroup_id = cgroup_id;
        evt->pid = bpf_get_current_pid_tgid() >> 32;
        evt->timestamp_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        __builtin_memcpy(&evt->path, buf, sizeof(evt->path));
        bpf_ringbuf_submit(evt, 0);
    }

    /* 8. Deny the open */
    return -EPERM;
}

char __license[] SEC("license") = "GPL";
