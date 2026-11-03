//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define PROC_SUPER_MAGIC 0x9fa0

/* Bit flags for cgroup_proc_config.flags */
#define FLAG_MONITORED       1
#define FLAG_ALLOW_PROC_READ 2
/* FLAG_OBSERVE_ONLY: emit the ringbuf event but DON'T deny the
 * /proc/<pid>/mem open. For sandboxed detonation, where we want to
 * record the injection attempt without killing the workload that
 * makes it. Mirrors credwatch.c's FLAG_OBSERVE_ONLY. */
#define FLAG_OBSERVE_ONLY    4

struct cgroup_proc_config {
    __u8 flags;
} __attribute__((packed));

struct proc_mem_event {
    __u64 cgroup_id;
    __u32 pid;
    char  comm[16];
    char  path[64];
    __u64 timestamp_ns;
    /* Appended (ABI v2, 108 bytes): registered container cgroup id; differs
     * from cgroup_id (the task's leaf) for a task in a descendant cgroup. */
    __u64 container_cgroup_id;
} __attribute__((packed));

/* Cgroup IDs of monitored containers — pre-filter to skip host processes.
 * Value is cgroup_proc_config (flags byte), not a simple presence flag,
 * because we need the allow_proc_read exemption per container. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);                       /* cgroup_id */
    __type(value, struct cgroup_proc_config);
} known_containers SEC(".maps");

/* Maximum absolute cgroup level (root = 0) at which a registered
 * container cgroup is matched as an ANCESTOR of the current task's
 * cgroup. The exact (leaf) lookup is always tried first and has no
 * depth limit; the ancestor walk exists so that a process which mkdirs
 * a child cgroup and moves itself into it (privileged / dind jobs, or
 * anything with a writable cgroupfs) stays covered.
 *
 * The bound is on the ABSOLUTE level of the registered container, not
 * on how deep the attacker nests: ancestors are probed by absolute level
 * 0..N-1 and the probe stops at the task's own level, so no amount of
 * nesting below the container escapes. 16 covers systemd slices, a
 * kubelet-in-container (KIND) layout and a nested runtime on top of it.
 * A container registered deeper than this still gets exact matching.
 *
 * Cost: the loop runs only when the leaf lookup misses, performs at most
 * one helper call + one hash lookup per level up to the task's level,
 * and is a flat unrolled loop of 16 small iterations: it does not touch
 * the suffix scan, so it adds a fixed, small amount to the verifier's
 * instruction budget. */
#define MAX_ANCESTOR_LEVEL 16

/* find_container resolves the registered container cgroup that the
 * current task belongs to. leaf is bpf_get_current_cgroup_id(); on
 * success *match is the container's cgroup id (== leaf for an exact
 * match, an ancestor id otherwise) and the container's config is
 * returned. The leaf is tried first, then ancestors from the nearest
 * one upwards; the first registered one wins, so with nested registered
 * containers the INNERMOST (nearest) container's config applies. Requires bpf_get_current_ancestor_cgroup_id (5.7, same release
 * that introduced BPF LSM, so no new kernel requirement). */
static __always_inline struct cgroup_proc_config *find_container(__u64 leaf, __u64 *match)
{
    struct cgroup_proc_config *cfg = bpf_map_lookup_elem(&known_containers, &leaf);

    if (cfg) {
        *match = leaf;
        return cfg;
    }

    /* Pass 1: the task's own level. Ancestors at levels 0..depth-1 are
     * strict ancestors; depth defaults to MAX_ANCESTOR_LEVEL when the task
     * sits at or below the last probed level (all probed levels are then
     * strict ancestors). Single-pass "remember the last match" is
     * miscompiled by clang 14 (verifier: R1 !read_ok), hence two passes. */
    int depth = MAX_ANCESTOR_LEVEL;

#pragma unroll
    for (int lvl = 0; lvl < MAX_ANCESTOR_LEVEL; lvl++) {
        __u64 anc = bpf_get_current_ancestor_cgroup_id(lvl);

        if (anc == 0 || anc == leaf) {
            depth = lvl;
            break;
        }
    }

    /* Pass 2: nearest ancestor first, so the innermost registered
     * container wins. */
#pragma unroll
    for (int lvl = MAX_ANCESTOR_LEVEL - 1; lvl >= 0; lvl--) {
        if (lvl >= depth)
            continue;

        __u64 anc = bpf_get_current_ancestor_cgroup_id(lvl);

        cfg = bpf_map_lookup_elem(&known_containers, &anc);
        if (cfg) {
            *match = anc;
            return cfg;
        }
    }

    return 0;
}

/* Per-CPU scratch buffer for bpf_d_path output. Stack memory does not
 * allow variable-offset reads; per-CPU array map values do. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[128]);
} path_buf SEC(".maps");

/* Ring buffer for proc-mem read events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  /* 64KB */
} proc_mem_events SEC(".maps");

/* Count of ringbuf reserve failures (ring full): lost evidence. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} reserve_failures SEC(".maps");

/* Force clang to emit BTF for proc_mem_event. Without a live reference, the
 * ringbuf-reserve path uses void* and BTF drops the struct — which blocks
 * the userspace struct-size self-check at load time. Concrete instance
 * (not a pointer-with-used) for toolchain-stable BTF retention — see
 * egress.c __sock_owner_btf_hint comment for rationale. */
volatile const struct proc_mem_event __proc_mem_event_btf_hint;

/* is_proc_mem_path checks whether the resolved path is /proc/<pid>/mem.
 * Uses a bounded loop with constant-offset reads to avoid variable-offset
 * stack/map access that the BPF verifier rejects. The loop scans for
 * "/mem\0" starting after position 5 (past "/proc/"), which covers PID
 * strings of 1-10 digits. Matches /proc/1/mem, /proc/self/mem, etc.
 * Does NOT match /proc/1/meminfo or /proc/1/mounts. */
static __always_inline int is_proc_mem_path(const char *buf)
{
    /* Verify path starts with /proc/ */
    if (buf[0] != '/' || buf[1] != 'p' || buf[2] != 'r' ||
        buf[3] != 'o' || buf[4] != 'c' || buf[5] != '/')
        return 0;

    /* Scan for "/mem\0" from position 6 onward. PIDs are 1-7 digits
     * (default max 4194304), so "/" before "mem" is at positions 7-13.
     * Scan wider to cover /proc/self/mem and large PID namespaces. */
#pragma unroll
    for (int i = 6; i < 24; i++) {
        if (buf[i] == '/' && buf[i+1] == 'm' && buf[i+2] == 'e' &&
            buf[i+3] == 'm' && buf[i+4] == '\0')
            return 1;
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(proc_mem_file_open, struct file *file)
{
    /* 1. Cgroup pre-filter — skip non-container processes */
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 container_id;
    struct cgroup_proc_config *cfg = find_container(cgroup_id, &container_id);
    if (!cfg)
        return 0;

    /* 2. Exempt containers with allow_proc_read label */
    if (cfg->flags & FLAG_ALLOW_PROC_READ)
        return 0;

    /* 3. Fast-path: skip non-procfs opens. PROC_SUPER_MAGIC (0x9fa0) is
     * the superblock magic for procfs. Checking the inode's superblock
     * avoids the cost of bpf_d_path for 99.9% of opens. */
    __u64 magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
    if (magic != PROC_SUPER_MAGIC)
        return 0;

    /* 4. Resolve file path into per-CPU scratch buffer. The file argument
     * to lsm/file_open is a trusted pointer, so &file->f_path is valid
     * for bpf_d_path in non-sleepable LSM context (same pattern as
     * sock_attr.c). */
    __u32 zero = 0;
    char *buf = bpf_map_lookup_elem(&path_buf, &zero);
    if (!buf)
        return 0;

    long path_len = bpf_d_path(&file->f_path, buf, 128);
    if (path_len < 0)
        return 0;

    /* 5. Check if path is /proc/<pid>/mem using constant-offset reads */
    if (!is_proc_mem_path(buf))
        return 0;

    /* 6. Emit event to ring buffer */
    struct proc_mem_event *evt;
    evt = bpf_ringbuf_reserve(&proc_mem_events, sizeof(*evt), 0);
    if (evt) {
        evt->cgroup_id = cgroup_id;
        evt->container_cgroup_id = container_id;
        evt->pid = bpf_get_current_pid_tgid() >> 32;
        evt->timestamp_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        __builtin_memcpy(&evt->path, buf, sizeof(evt->path));
        bpf_ringbuf_submit(evt, 0);
    } else {
        __u64 *fails = bpf_map_lookup_elem(&reserve_failures, &zero);

        if (fails)
            *fails += 1;
    }

    /* 7. Deny the open — unless this container is in observe-only
     * mode, in which case the event above is enough and we let the
     * open proceed (sandboxed detonation: record, don't kill). */
    if (cfg->flags & FLAG_OBSERVE_ONLY)
        return 0;

    return -EPERM;
}

char __license[] SEC("license") = "GPL";