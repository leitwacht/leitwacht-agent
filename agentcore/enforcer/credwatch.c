//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

/* Inode type bits (not in vmlinux.h as macros). */
#define S_IFMT  0170000
#define S_IFDIR 0040000
#define S_IFREG 0100000

#define RENAME_EXCHANGE 2

/* credwatch_event.kind: which hook produced the event. */
#define CW_KIND_OPEN       0  /* file_open, path matched a watched suffix */
#define CW_KIND_RENAME     1  /* path_rename of a watched file/directory */
#define CW_KIND_LINK       2  /* path_link of a watched file */
#define CW_KIND_DPATH_FAIL 3  /* file_open, d_path failed, (parent,name) matched */

/* OR-ed into credwatch_event.kind when the match is in the report-only
 * class: the event is emitted but the access is always allowed, in every
 * mode. The low bits keep the CW_KIND_* hook identifier, so the event
 * struct layout is unchanged. */
#define CW_KIND_REPORT_ONLY 0x80

/* Class stored as the value of watched_suffixes / watched_pairs /
 * watched_dirs. 0 (absent) = not watched.
 * Userspace resolves a suffix listed in both classes to report-only and
 * never inserts an excluded suffix. When two DIFFERENT suffixes match
 * one path, match_suffix returns the longest (most specific) one, and
 * for (parent, name) pairs an exact (parent, name) entry wins over a
 * name-only entry; userspace never lets report-only downgrade a key a
 * watched suffix holds. The BPF program
 * keeps no running "best" across the unrolled scan: carrying a
 * variable through 127 branching iterations exceeds the verifier's
 * 1M-instruction budget. */
#define CW_CLASS_WATCHED     1  /* deny in enforce mode */
#define CW_CLASS_REPORT_ONLY 2  /* emit event, never deny */

#define PATH_BUF_LEN 512

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
    __u8  kind;                               /* CW_KIND_* */
} __attribute__((packed));

/* (parent directory name, file name) of a watched suffix, e.g.
 * {".ssh", "id_rsa"}. Used by the rename/link hooks and by the
 * d_path-failure path, which have a dentry but no resolved path. An
 * all-zero parent means "any directory" (suffixes with no parent
 * component, e.g. "/.vault-token"). */
struct pair_key {
    char parent[32];
    char name[64];
};

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

/* Watched (parent, name) pairs derived from watched_suffixes. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct pair_key);
    __type(value, __u8);
} watched_pairs SEC(".maps");

/* (grandparent, directory) pairs for directories that contain a watched
 * file (".ssh", (".config","gcloud"), ("rancher","k3s"), ...). Renaming
 * such a directory moves every watched file under it out of reach of the
 * suffix match. Same key shape as watched_pairs: an all-zero parent
 * means "any parent". Generic directory names only appear with a
 * non-empty parent. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct pair_key);
    __type(value, __u8);
} watched_dirs SEC(".maps");

/* Per-CPU scratch buffer for bpf_d_path output. Stack memory does not
 * allow variable-offset reads; per-CPU array map values do. 512 bytes
 * so that ENAMETOOLONG is practically unreachable (deep pnpm/node_modules
 * trees exceed 128). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[PATH_BUF_LEN]);
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

/* match_suffix returns the class (CW_CLASS_*) of the longest watched
 * suffix the resolved path ends with, or 0 for none. Candidates are
 * tried from the earliest '/' in the window, so the longest matching
 * suffix decides. Only the last 128 bytes of the path can hold a suffix (they
 * are at most 63 bytes), so only that tail window is scanned; every '/'
 * in it is tried as a suffix start. Position 0 is included, so a path
 * equal to an absolute suffix matches.
 *
 * path is the 512-byte per-CPU scratch buffer; all indexing is masked
 * with PATH_BUF_LEN-1 so the verifier can bound the variable offsets. */
static __always_inline __u8 match_suffix(const char *path, __u32 path_len)
{
    __u32 ws = path_len > 128 ? path_len - 128 : 0;

    if (ws > PATH_BUF_LEN - 128)
        ws = PATH_BUF_LEN - 128;

#pragma unroll
    for (int pos = 0; pos < 127; pos++) {
        __u32 idx = ws + pos;

        if (idx >= path_len)
            break;

        /* All watched suffixes begin with '/'. */
        if (path[idx & (PATH_BUF_LEN - 1)] != '/')
            continue;

        /* One helper call copies the candidate (up to 63 bytes, stopping
         * at the path's NUL); the zeroed stack buffer pads the key. */
        char suffix[64] = {};

        (void)bpf_probe_read_kernel_str(suffix, sizeof(suffix),
                                        path + (idx & (PATH_BUF_LEN - 1)));

        __u8 *found = bpf_map_lookup_elem(&watched_suffixes, &suffix);
        if (found)
            return *found;
    }

    return 0;
}

/* read_name reads a dentry's name into out (sz bytes, NUL-terminated).
 * Returns the length, or 0 on error. */
static __always_inline int read_name(struct dentry *dentry, char *out, __u32 sz)
{
    struct qstr dname;

    if (!dentry)
        return 0;
    if (bpf_core_read(&dname, sizeof(dname), &dentry->d_name))
        return 0;

    long len = bpf_probe_read_kernel_str(out, sz, dname.name);
    if (len < 0)
        return 0;

    return len;
}

/* fill_pair fills k (which must be zero-initialised) with the dentry's
 * parent directory name and its own name. Returns 0 if the name cannot
 * be read. */
static __always_inline void fill_parent(struct dentry *d, struct pair_key *k)
{
    struct dentry *parent = BPF_CORE_READ(d, d_parent);

    if (parent && parent != d)
        (void)read_name(parent, k->parent, sizeof(k->parent));
}

static __always_inline int fill_pair(struct dentry *d, struct pair_key *k)
{
    if (read_name(d, k->name, sizeof(k->name)) == 0)
        return 0;

    fill_parent(d, k);

    return 1;
}

/* pair_class returns the class of (parent, name) in map_. An exact
 * (parent, name) entry decides; the name-only entry (empty parent) is
 * consulted only on a miss, so a loose report-only "/credentials" can
 * never override an exact watched "/.aws/credentials". */
#define PAIR_CLASS(map_, k_)                                           \
    ({                                                                 \
        __u8 _cls = 0;                                                 \
        __u8 *_v = bpf_map_lookup_elem(&(map_), (k_));                 \
        if (_v) {                                                      \
            _cls = *_v;                                                \
        } else {                                                       \
            struct pair_key _any = {};                                 \
            __builtin_memcpy(_any.name, (k_)->name, sizeof(_any.name)); \
            _v = bpf_map_lookup_elem(&(map_), &_any);                  \
            if (_v)                                                    \
                _cls = *_v;                                            \
        }                                                              \
        _cls;                                                          \
    })

static __always_inline __u8 pair_class(const struct pair_key *k)
{
    return PAIR_CLASS(watched_pairs, k);
}

/* emit_credwatch publishes one event. src is copied into the 128-byte
 * path field; n (a compile-time constant after inlining) is how many
 * bytes. */
static __always_inline void emit_credwatch(__u64 cgroup_id, __u8 kind, __u8 cls,
                                           const void *src, __u32 n)
{
    struct credwatch_event *evt;

    evt = bpf_ringbuf_reserve(&credwatch_events, sizeof(*evt), 0);
    if (!evt) {
        __u32 z = 0;
        __u64 *c = bpf_map_lookup_elem(&reserve_failures, &z);

        if (c)
            *c += 1;
        return;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->cgroup_id = cgroup_id;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->kind = cls == CW_CLASS_REPORT_ONLY ? (kind | CW_KIND_REPORT_ONLY) : kind;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    (void)bpf_probe_read_kernel(&evt->path, n, src);
    bpf_ringbuf_submit(evt, 0);
}

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

static __always_inline int verdict(struct cgroup_proc_config *cfg, __u8 cls)
{
    /* Report-only paths are never denied, in any mode. */
    if (cls == CW_CLASS_REPORT_ONLY)
        return 0;
    if (cfg->flags & FLAG_OBSERVE_ONLY)
        return 0;
    return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(credwatch_file_open, struct file *file)
{
    __u64 cgroup_id;
    struct cgroup_proc_config *cfg = watched_container(&cgroup_id);
    if (!cfg)
        return 0;

    /* Only regular files hold credentials. */
    __u16 mode = BPF_CORE_READ(file, f_inode, i_mode);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    /* Skip pseudo-filesystems (cost of bpf_d_path for no benefit). */
    __u64 magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
    if (magic == PROC_SUPER_MAGIC || magic == SYSFS_MAGIC ||
        magic == CGROUP_SUPER_MAGIC || magic == DEBUGFS_MAGIC ||
        magic == DEVPTS_SUPER_MAGIC)
        return 0;

    /* Dentry filename pre-filter: avoids bpf_d_path for the 99%+ of
     * opens whose file name is not a watched name. */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct pair_key pk = {};

    if (read_name(dentry, pk.name, sizeof(pk.name)) == 0)
        return 0;

    __u8 *fname_found = bpf_map_lookup_elem(&watched_filenames, &pk.name);
    if (!fname_found)
        return 0;

    /* Only a prefilter hit pays for the parent-name read. */
    fill_parent(dentry, &pk);

    __u32 zero = 0;
    char *buf = bpf_map_lookup_elem(&path_buf, &zero);
    long path_len = -1;

    if (buf)
        path_len = bpf_d_path(&file->f_path, buf, PATH_BUF_LEN);

    if (path_len < 0) {
        /* The full path could not be resolved (longer than the buffer).
         * Fall back to the (parent, name) pair: a match is treated as
         * a hit, anything else is let through, so only genuinely
         * suspicious opens are denied. */
        __u8 pcls = pair_class(&pk);

        if (!pcls)
            return 0;

        emit_credwatch(cgroup_id, CW_KIND_DPATH_FAIL, pcls, pk.name, 64);

        return verdict(cfg, pcls);
    }

    if (path_len > PATH_BUF_LEN)
        path_len = PATH_BUF_LEN;

    __u8 cls = match_suffix(buf, path_len);

    if (!cls)
        return 0;

    /* Report the tail of the path (the part that matched). */
    __u32 tail = path_len > 128 ? path_len - 128 : 0;

    if (tail > PATH_BUF_LEN - 128)
        tail = PATH_BUF_LEN - 128;

    emit_credwatch(cgroup_id, CW_KIND_OPEN, cls, buf + tail, 128);

    return verdict(cfg, cls);
}

/* dentry_verdict is shared by the path_rename and path_link hooks. A
 * credential file can be renamed or hard-linked to a name the file_open
 * prefilter does not watch, and its directory can be renamed out from
 * under the suffix match. The checks are deliberately narrow to avoid
 * killing legitimate builds:
 *   - regular files: the (parent directory name, file name) pair must be
 *     a watched pair (".ssh"/"id_rsa"), not just a watched file name;
 *   - directories: (parent, name) must be a watched directory pair, i.e.
 *     the directory holding a watched file (".ssh", ".config/gcloud",
 *     "rancher/k3s", ...). */
static __always_inline int dentry_verdict(struct dentry *d, __u8 kind)
{
    __u64 cgroup_id;
    struct cgroup_proc_config *cfg = watched_container(&cgroup_id);
    if (!cfg)
        return 0;

    struct inode *inode = BPF_CORE_READ(d, d_inode);
    if (!inode)
        return 0;

    __u16 mode = BPF_CORE_READ(inode, i_mode);
    __u16 type = mode & S_IFMT;
    struct pair_key pk = {};

    if (!fill_pair(d, &pk))
        return 0;

    __u8 cls;

    if (type == S_IFREG) {
        cls = pair_class(&pk);
    } else if (type == S_IFDIR) {
        /* Parent directories of watched (class 1) and report-only
         * (class 2) suffixes are populated. */
        cls = PAIR_CLASS(watched_dirs, &pk);
    } else {
        return 0;
    }

    if (!cls)
        return 0;

    emit_credwatch(cgroup_id, kind, cls, pk.name, 64);

    return verdict(cfg, cls);
}

SEC("lsm/path_rename")
int BPF_PROG(credwatch_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
    int r = dentry_verdict(old_dentry, CW_KIND_RENAME);

    if (r)
        return r;

    /* RENAME_EXCHANGE also moves new_dentry into the old location. */
    if (flags & RENAME_EXCHANGE)
        return dentry_verdict(new_dentry, CW_KIND_RENAME);

    return 0;
}

SEC("lsm/path_link")
int BPF_PROG(credwatch_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    return dentry_verdict(old_dentry, CW_KIND_LINK);
}

char __license[] SEC("license") = "GPL";
