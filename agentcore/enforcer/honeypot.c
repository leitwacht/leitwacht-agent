//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct honeypot_key {
    __u32 dev;
    __u64 ino;
} __attribute__((packed));

struct honeypot_event {
    __u64 cgroup_id;
    __u32 pid;
    __u32 dev;
    __u64 ino;
    char comm[16];
    __u64 timestamp_ns;
} __attribute__((packed));

/* Cgroup IDs of monitored containers — pre-filter to skip host processes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    /* cgroup_id */
    __type(value, __u8);   /* presence flag */
} known_containers SEC(".maps");

/* Honeypot file inodes — (dev, ino) pairs loaded by userspace */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct honeypot_key);
    __type(value, __u8);   /* presence flag */
} honeypot_inodes SEC(".maps");

/* Ring buffer for honeypot violation events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  /* 64KB */
} honeypot_events SEC(".maps");

/* Force clang to emit BTF for honeypot_event. Without a live reference, the
   ringbuf-reserve path uses void* and BTF drops the struct — which blocks
   the userspace struct-size self-check at load time. */
struct honeypot_event *__honeypot_event_btf_hint __attribute__((used));

SEC("lsm/file_open")
int BPF_PROG(honeypot_file_open, struct file *file)
{
    /* 1. Cgroup pre-filter — skip non-container processes */
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *found = bpf_map_lookup_elem(&known_containers, &cgroup_id);
    if (!found)
        return 0;

    /* 2. Extract (dev, ino) from file->f_inode */
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct honeypot_key key = {};
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.ino = BPF_CORE_READ(inode, i_ino);

    /* 3. Lookup in honeypot map */
    __u8 *is_honeypot = bpf_map_lookup_elem(&honeypot_inodes, &key);
    if (!is_honeypot)
        return 0;

    /* 4. Emit event to ring buffer */
    struct honeypot_event *evt;
    evt = bpf_ringbuf_reserve(&honeypot_events, sizeof(*evt), 0);
    if (evt) {
        evt->cgroup_id = cgroup_id;
        evt->pid = bpf_get_current_pid_tgid() >> 32;
        evt->dev = key.dev;
        evt->ino = key.ino;
        evt->timestamp_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_ringbuf_submit(evt, 0);
    }

    /* 5. Deny the open */
    return -EPERM;
}

char __license[] SEC("license") = "GPL";
