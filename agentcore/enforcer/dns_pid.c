//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define BINARY_PATH_LEN 256

/* DNS attribution record: populated by kprobes on udp_sendmsg and
   tcp_connect, read synchronously from userspace by the DNS proxy when
   handling each query. Keyed by (netns_cookie, src_port).

   Why the key includes netns_cookie: Linux ephemeral port ranges are
   per-netns. Two containers in different netns can concurrently use the
   same src_port (say 41234) for their DNS query — a port-only key would
   silently overwrite one attribution with the other. Netns is exactly
   the scope within which src_port uniquely identifies a flow (the
   kernel serialises port allocation per-netns), so (netns_cookie,
   src_port) is the invariant-matching key.

   Capacity: 65536 entries. Upper-bounded by N_netns × ephemeral_port
   range (~28k per netns). Typical CI hosts run dozens of concurrent
   containers, comfortably within the cap. Synchronous lookup via bpf(2)
   syscall from the proxy is race-free by construction: the kprobe
   commits this entry strictly before the packet leaves the kernel, and
   the proxy's lookup strictly follows the packet arriving at its
   socket. */
struct dns_pid_attribution {
    __u32 pid;
    char  comm[16];
    char  parent_comm[16];
    __u64 cgroup_id;
    __u64 ts_ns;
    __u8  flags;               /* 1=UDP, 2=TCP */
} __attribute__((packed));

/* Explicit padding to a 16-byte, 8-byte-aligned layout so BPF-side C
   struct layout and userspace Go struct layout match byte-for-byte.
   Natural alignment would give the same 16 bytes but the explicit
   padding makes the contract unmistakable to future editors. */
struct dns_attr_key {
    __u64 netns_cookie;
    __u16 src_port;
    __u16 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_attr_key);
    __type(value, struct dns_pid_attribution);
} dns_pid_attribution SEC(".maps");

/* Per-process binary-path cache, populated by exec hooks (LSM primary
   via bpf_d_path, sched_process_exec tracepoint fallback). Separate
   map so we don't duplicate a 256-byte binary_path into every
   per-port attribution entry. Proxy reads this by pid after reading
   the attribution hash by src_port. */
struct process_info {
    char  binary_path[BINARY_PATH_LEN];
    __u64 exec_ts;
    __u64 cgroup_id;
    __u64 exec_id;             /* task->self_exec_id at exec: identifies one exec */
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info SEC(".maps");

/* Cgroup IDs of monitored containers — pre-filter to skip host traffic. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} dns_known_cgroups SEC(".maps");

static __always_inline void record_dns_attribution(struct sock *sk, __u64 cgroup_id, __u16 src_port, __u8 flags)
{
    if (src_port == 0)
        return; /* defense-in-depth: with the fexit hook, autobind has
                   already committed a port on successful sends, so this
                   branch should be unreachable. Kept to avoid polluting
                   the hash with key=0 if some future edge case leaves
                   skc_num unset. */

    /* Zero-init so any helper failure below leaves a valid (if empty)
       field rather than stack garbage. The explicit (void) casts on
       helper calls document that we've considered the return value and
       chosen graceful degradation over error propagation. */
    struct dns_pid_attribution attr = {};

    attr.pid       = bpf_get_current_pid_tgid() >> 32;
    attr.cgroup_id = cgroup_id;
    attr.ts_ns     = bpf_ktime_get_ns();
    attr.flags     = flags;

    (void)bpf_get_current_comm(&attr.comm, sizeof(attr.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent)
        (void)bpf_probe_read_kernel_str(&attr.parent_comm, sizeof(attr.parent_comm), &parent->comm);

    /* Read the netns cookie directly from the socket's sock_net via
       CO-RE rather than calling bpf_get_netns_cookie(). The helper is
       only available to certain program types (cgroup/sockops); it
       isn't exposed to fexit/tracing on many kernels including 6.19.
       sock_net(sk)->net_cookie is what SO_NETNS_COOKIE reports on
       userspace side, so reading it directly matches the userspace
       value byte-for-byte with no kernel-version dependency beyond the
       field being present (Linux 5.15+; our kernel floor is 6.0). */
    __u64 cookie = BPF_CORE_READ(sk, __sk_common.skc_net.net, net_cookie);

    /* Zero-init the key struct (including trailing padding) so the
       bytes that BPF hashes match what userspace sends via
       getsockopt(SO_NETNS_COOKIE) + same-shape key. Designated
       initialiser guarantees padding is zero (C11 6.7.9 §21). */
    struct dns_attr_key key = {
        .netns_cookie = cookie,
        .src_port     = src_port,
    };

    /* Update can fail if the LRU can't evict (all slots pinned in-flight).
       At 65536 entries vs ~28k ephemeral ports per netns that's a
       theoretical worst case; if it happens the proxy's lookup will miss
       and the query is recorded without attribution. */
    (void)bpf_map_update_elem(&dns_pid_attribution, &key, &attr, BPF_ANY);
}

/* IPv4 only — udp_sendmsg is the IPv4 UDP send path; udpv6_sendmsg is
   separate. Not a gap in practice because the egress filter
   (egress.c) drops all non-loopback IPv6 at the cgroup_skb hook, so
   IPv6 DNS cannot complete from a tracked container.

   Hooked at fexit rather than entry because glibc's res_send() uses
   unconnected UDP via sendto(): at udp_sendmsg entry, sk->skc_num is
   still 0 — autobind hasn't run yet. At fexit, autobind has
   committed the ephemeral port and sk->skc_num is populated. Entry
   hook worked for c-ares/libuv (they connect() before send() so
   bind has already happened) but silently dropped every glibc-path
   DNS query via the src_port==0 skip — the dominant case in
   production traffic from Go toolchains, pip, npm, and apt. */
SEC("fexit/udp_sendmsg")
int BPF_PROG(dns_pid_sendmsg, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
    /* Skip sends that errored before the packet left the kernel — no
       attribution worth recording and skc_num may not be populated. */
    if (ret < 0)
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *found = bpf_map_lookup_elem(&dns_known_cgroups, &cgroup_id);
    if (!found)
        return 0;

    /* Destination port: connected socket fills skc_dport; unconnected
       sendto() (musl, glibc) passes it via msghdr->msg_name. The
       sockaddr_in / sockaddr_in6 port offset is identical (2). */
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 dport_h = bpf_ntohs(dport);

    if (dport_h == 0) {
        struct sockaddr_in *addr = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
        if (addr) {
            __be16 sin_port = 0;
            /* Read failure leaves sin_port=0; dport_h=0 then fails the
               port-53 filter below, so we silently skip the event —
               preferable to emitting attribution for an unknown port. */
            (void)bpf_probe_read_kernel(&sin_port, sizeof(sin_port), &addr->sin_port);
            dport_h = bpf_ntohs(sin_port);
        }
    }

    if (dport_h != 53 && dport_h != 15353)
        return 0;

    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    record_dns_attribution(sk, cgroup_id, sport, 1);

    return 0;
}

/* tcp_connect is called from both tcp_v4_connect and tcp_v6_connect
   after dport and sport are populated (inet_hash_connect has already
   run). One probe covers both address families. */
SEC("kprobe/tcp_connect")
int BPF_KPROBE(dns_pid_tcp_connect, struct sock *sk)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *found = bpf_map_lookup_elem(&dns_known_cgroups, &cgroup_id);
    if (!found)
        return 0;

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (bpf_ntohs(dport) != 53)
        return 0;

    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    record_dns_attribution(sk, cgroup_id, sport, 2);

    return 0;
}

/* Primary binary_path source: BPF LSM on bprm_committed_creds. Direct
   field access preserves LSM pointer-trust tracking required by the
   verifier for bpf_d_path. bpf_d_path walks to current->fs->root so
   container processes get container-relative canonical paths. */
SEC("lsm/bprm_committed_creds")
int BPF_PROG(dns_pid_bprm, struct linux_binprm *bprm)
{
    if (!bprm || !bprm->file)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_info pi = {};
    pi.exec_ts   = bpf_ktime_get_ns();
    pi.cgroup_id = bpf_get_current_cgroup_id();
    pi.exec_id   = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), self_exec_id);

    /* Cast drops the const qualifier that clang adds through the
       BPF_PROG-expanded `const struct linux_binprm *` param. bpf_d_path
       doesn't modify the path argument — kernel signature is non-const
       for backward-compat reasons, not because it writes through. */
    long n = bpf_d_path((struct path *)&bprm->file->f_path,
                        pi.binary_path, sizeof(pi.binary_path));
    if (n < 0)
        return 0; /* d_path failed; tracepoint fallback may still fill in */

    (void)bpf_map_update_elem(&process_info, &pid, &pi, BPF_ANY);
    return 0;
}

/* Fallback binary_path source: sched_process_exec tracepoint reading
   the raw __data_loc_filename. This is the path the caller passed to
   execve() — kernel-recorded, so not argv[0] (which execve lets
   callers set arbitrarily), but still the caller's chosen path
   string, not a symlink-resolved canonical path. The LSM path above
   gets the kernel-resolved canonical path via bpf_d_path; this
   fallback is what we ship with when the LSM program can't load.
   The LSM hook (bprm_committed_creds) fires a few microseconds
   before this tracepoint for the same exec and stores the canonical
   path. This fallback overwrites an existing entry (BPF_ANY, so a
   re-exec or recycled pid never keeps a stale path) EXCEPT when the
   entry carries the same task->self_exec_id, which means the LSM
   already recorded this very exec. */
SEC("tracepoint/sched/sched_process_exec")
int dns_pid_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct process_info pi = {};
    pi.exec_ts   = bpf_ktime_get_ns();
    pi.cgroup_id = bpf_get_current_cgroup_id();
    pi.exec_id   = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), self_exec_id);

    unsigned short file_off = ctx->__data_loc_filename & 0xFFFF;
    (void)bpf_probe_read_kernel_str(&pi.binary_path, sizeof(pi.binary_path),
                                    (char *)ctx + file_off);

    struct process_info *cur = bpf_map_lookup_elem(&process_info, &pid);
    if (cur && cur->exec_id == pi.exec_id)
        return 0; /* LSM already stored the canonical path for this exec */

    (void)bpf_map_update_elem(&process_info, &pid, &pi, BPF_ANY);
    return 0;
}

/* Drop the process_info entry when the process dies, so PID reuse
   cannot inherit it. sched_process_exit fires per thread; the entry is
   keyed by tgid and belongs to the whole thread group, so delete only
   when the last thread is gone (signal->live reaches zero). Keying on
   "the leader thread exited" would be wrong in both directions: a
   leader can exit while other threads run, and exec from a non-leader
   thread makes it the leader. */
SEC("tracepoint/sched/sched_process_exit")
int dns_pid_exit(void *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    (void)bpf_map_delete_elem(&process_info, &pid);
    return 0;
}

char __license[] SEC("license") = "GPL";
