//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define DOT_PORT 853
#define BINARY_PATH_LEN 256

/* struct sock is opaque; only used as a handle for bpf_sk_storage_get. */
struct sock;

/* Minimal task_struct decl: only flags is read (PF_KTHREAD check in
 * skip_softirq_attribution). preserve_access_index makes the field
 * offset CO-RE-relocated against the running kernel's BTF. */
struct task_struct {
    unsigned int flags;
} __attribute__((preserve_access_index));

struct allow_key {
    __u32 ip;
    __u16 port;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct allow_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} config SEC(".maps");

#define DROP_REASON_POLICY   1
#define DROP_REASON_SINKHOLE 2

/* pid + comm capture attribution for packet violations. cgroup_skb/egress
   runs in process context for send syscalls (sendmsg/sendto/connect), so
   bpf_get_current_pid_tgid() and bpf_get_current_comm() name the caller.
   Caveat: for softirq-context emissions (TCP retransmits, ACKs,
   keepalives), `current` is whatever task was interrupted — a kernel
   worker or unrelated process. Attribution for those events is noisy.
   The dominant case (first SYN drops, UDP sendmsg) is in process context
   and attributes correctly. Userspace also does a second lookup against
   process_info[pid] for binary_path, mirroring the DNS proxy's
   LookupWithBinary two-step. */
struct drop_event {
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;
    __u64 cgroup_id;
    __u8  reason;           /* DROP_REASON_* */
    __u32 pid;              /* tgid of connecting task (from sk_storage)
                               or current task (fallback); 0 if none */
    char  comm[16];         /* process name, "" if unavailable */
    char  binary_path[BINARY_PATH_LEN]; /* bpf_d_path result from LSM
                                           capture, "" if unavailable */
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} drop_events SEC(".maps");

/* Force clang to emit BTF for drop_event. Without a live reference, the
   ringbuf-reserve path uses void* and BTF drops the struct — which blocks
   the userspace struct-size self-check at load time. Concrete instance
   (not a pointer-with-used) for toolchain-stable BTF retention. */
volatile const struct drop_event __drop_event_btf_hint;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct allow_key);
    __type(value, __u64);
    __uint(max_entries, 4096);
} drop_dedup SEC(".maps");

/* Operator-denied IPs. Checked before trusted_nets so deny overrides trust.
   Port=0 means deny all ports for that IP. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct allow_key);
    __type(value, __u8);
    __uint(max_entries, 4096);
} denied_ips SEC(".maps");

/* Per-socket attribution.
 *
 * Populated by LSM hooks (socket_connect, socket_sendmsg)
 * that always run in process context — current is guaranteed to be the
 * real socket owner. Read from cgroup_skb/egress where, in softirq
 * context (TCP retransmits, keepalives, delayed ACKs), current is
 * whichever task got preempted on that CPU and would misattribute.
 *
 * Kernel frees the entry when the socket is destroyed. No LRU, no
 * userspace cleanup, no size tuning. */
struct sock_owner {
    __u64 cgroup_id;
    __u32 pid;
    __u32 _reserved;
    char  comm[16];
    char  binary_path[BINARY_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct sock_owner);
} sock_owners SEC(".maps");

/* sock_known_cgroups (the LSM-side gating filter) lives in sock_attr.c.
 * The egress program never reads it — only the LSM hooks do, to decide
 * which sockets get sk_storage. Userspace writes go through the
 * singleton LSM handle (see linuxLSMHandle.AddSockKnownCgroup). */

/* Force clang to emit BTF for sock_owner so the userspace struct-size
 * verifier can match it against the Go-side constant. A concrete
 * volatile-const instance is more reliable than a pointer-with-used:
 * clang historically has recursed through volatile-const instances
 * into field types consistently, whereas pointer-with-used has
 * varied across clang 13→18 for the pointee. */
volatile const struct sock_owner __sock_owner_btf_hint;

/* LPM trie for trusted CIDRs (e.g. Docker bridge, k8s pod network).
   Traffic to these networks is always allowed without DNS resolution. */
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, 64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_nets SEC(".maps");

/* PF_KTHREAD: set on every kernel thread (swapper, ksoftirqd, kworker,
   migration, rcu_N, irq_N). Stable across kernels since before 3.0. */
#define PF_KTHREAD 0x00200000U

/* skip_softirq_attribution returns 1 if the caller is a kernel thread,
   which is the dominant form of misattribution for softirq-context
   egress events (retransmits landing on idle CPUs → current = swapper,
   deferred softirqs on ksoftirqd, timer-queued work on kworker). Early
   returning here skips the whole event path — no ringbuf reserve, no
   dedup map write, no userspace wakeup. Saves ~500ns per suppressed
   event; PF_KTHREAD read is ~15ns.

   We considered also checking preempt_count & SOFTIRQ_MASK to catch
   softirqs that preempt user tasks, but thread_info.preempt_count
   isn't reliably CO-RE-resolvable across kernel builds on 6.x (per-
   CPU optimisations relocate the field). The userspace comm-prefix
   filter in platform_linux.go stays as belt-and-suspenders for that
   residual case. */
static __always_inline int skip_softirq_attribution(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u32 flags = BPF_CORE_READ(task, flags);
    return (flags & PF_KTHREAD) ? 1 : 0;
}

static __always_inline void emit_drop_event(struct __sk_buff *skb,
                                            __u32 ip, __u16 port, __u8 proto,
                                            __u64 cgroup_id, __u8 reason) {
    /* Dedup first: 1-second window on (ip, port). Runs before any
     * attribution work so we don't pay the sk_storage lookup or the
     * softirq guard cost on the ~99% of events that are retransmits
     * of an already-published drop on a failed connection. */
    struct allow_key dedup_key = {.ip = ip, .port = port};
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&drop_dedup, &dedup_key);

    if (last && (now - *last) < 1000000000ULL) /* 1 second */
        return;

    /* Attribution precedence:
     *   1. sk_storage (captured at LSM socket_connect / sendmsg, always
     *      in process context). Authoritative — immune to softirq
     *      context where `current` would be the preempted task.
     *   2. bpf_get_current_* fallback when sk_storage is unavailable
     *      (pre-existing sockets from before agent attach, skb->sk
     *      NULL on some forwarded packets, LSM not attached on this
     *      kernel). Paired with skip_softirq_attribution below so
     *      fallback events aren't published with kthread noise.
     *
     * skb->sk is a trusted bpf_sock in cgroup_skb/egress;
     * bpf_sk_storage_get's arg2 accepts ARG_PTR_TO_SOCK_COMMON (bpf_sock
     * satisfies), so pass it directly with no cast to preserve the
     * verifier's trust relation. */
    struct sock_owner *owner = NULL;
    if (skb && skb->sk) {
        owner = bpf_sk_storage_get(&sock_owners, skb->sk, NULL, 0);
    }

    if (!owner && skip_softirq_attribution()) {
        /* Fallback-only: softirq with no sk_storage means `current`
         * is an arbitrary preempted task. Publishing would misattribute;
         * skip. LSM-attached deployments rarely land here after the
         * first post-attach socket on a container. */
        return;
    }

    struct drop_event *ev = bpf_ringbuf_reserve(&drop_events, sizeof(struct drop_event), 0);
    if (!ev)
        return;

    /* Ringbuf reserve returns uninitialised slot memory — stale
     * bytes from the previous event at this slot leak into fields
     * we don't explicitly write below. Zero the whole struct first
     * so the fallback branch (which doesn't set binary_path) can't
     * publish the binary of an unrelated prior process. */
    __builtin_memset(ev, 0, sizeof(*ev));

    ev->dst_ip = ip;
    ev->dst_port = port;
    ev->protocol = proto;
    ev->reason = reason;

    if (owner) {
        /* Authoritative attribution from LSM capture. Use the
         * owner's cgroup_id rather than the caller's: on softirq-
         * origin packets, bpf_get_current_cgroup_id() at egress_filter
         * entry would have been the preempted task's cgroup, not the
         * socket creator's. The userspace recorder lookup keys on the
         * socket creator's cgroup. */
        ev->cgroup_id = owner->cgroup_id;
        ev->pid = owner->pid;
        __builtin_memcpy(&ev->comm, &owner->comm, sizeof(ev->comm));
        __builtin_memcpy(&ev->binary_path, &owner->binary_path,
                         sizeof(ev->binary_path));
    } else {
        /* Fallback to current. binary_path stays empty (zeroed above)
         * when we can't resolve it — userspace falls back to
         * process_info[pid] in that case. */
        ev->cgroup_id = cgroup_id;
        ev->pid = bpf_get_current_pid_tgid() >> 32;
        (void)bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    }

    bpf_ringbuf_submit(ev, 0);
    (void)bpf_map_update_elem(&drop_dedup, &dedup_key, &now, BPF_ANY);
}

static __always_inline int account_bytes(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, skb->len);
    return 0;
}

static __always_inline __u8 get_mode(void) {
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&config, &key);
    if (mode)
        return *mode;
    return 0; /* default: block */
}

/* apply_drop: emit a drop event and return the verdict to the caller.
 * Consolidates the emit + mode-check + bytes-accounting trailer that
 * used to appear inline at every drop site in egress_filter. Audit
 * mode returns 1 (let packet through but record and account); block
 * mode returns 0 (drop). */
static __always_inline int apply_drop(struct __sk_buff *skb, __u32 ip,
                                      __u16 port, __u8 proto,
                                      __u64 cgroup_id, __u8 reason) {
    emit_drop_event(skb, ip, port, proto, cgroup_id, reason);

    if (get_mode() == 1) {
        account_bytes(skb);
        return 1; /* audit: allow but record */
    }

    return 0; /* block: drop */
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    /* Use bpf_skb_load_bytes for cgroup_skb — direct packet access is
       unreliable across kernel versions for this program type. */

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    __u8 ver_ihl;
    if (bpf_skb_load_bytes(skb, 0, &ver_ihl, 1) < 0)
        return 1; /* allow: can't read */

    __u8 version = ver_ihl >> 4;

    /* IPv6: drop all except loopback (::1) */
    if (version == 6) {
        struct in6_addr daddr;
        /* IPv6 dest addr starts at offset 24 in the IPv6 header */
        if (bpf_skb_load_bytes(skb, 24, &daddr, sizeof(daddr)) < 0)
            return 1;

        if (daddr.in6_u.u6_addr32[0] == 0 &&
            daddr.in6_u.u6_addr32[1] == 0 &&
            daddr.in6_u.u6_addr32[2] == 0 &&
            daddr.in6_u.u6_addr32[3] == bpf_htonl(1))
            return 1; /* allow loopback */

        __u8 mode = get_mode();
        if (mode == 1) {
            account_bytes(skb);
            return 1; /* audit: allow */
        }
        return 0; /* block: drop all IPv6 */
    }

    if (version != 4)
        return 1; /* allow non-IP */

    /* Read IPv4 header fields we need */
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
        return 1;

    __u32 dst_ip = iph.daddr;
    __u8 protocol = iph.protocol;
    __u32 ip_hlen = iph.ihl * 4;
    __u16 dst_port = 0;

    /* Extract destination port for TCP/UDP */
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        /* Destination port is at offset 2 in both TCP and UDP headers */
        __be16 dport;
        if (bpf_skb_load_bytes(skb, ip_hlen + 2, &dport, sizeof(dport)) < 0)
            return 1;
        dst_port = bpf_ntohs(dport);
    }

    /* --- Hard blocks: checked BEFORE the allow map so DNS rebinding can't bypass them --- */

    /* Cloud metadata: 169.254.169.254 — always block regardless of allow map.
       Prevents DNS rebinding attacks (attacker domain resolving to metadata IP). */
    if (dst_ip == bpf_htonl(0xA9FEA9FE))
        return apply_drop(skb, dst_ip, dst_port, protocol, cgroup_id, DROP_REASON_POLICY);

    /* DoT: always block port 853 */
    if (dst_port == DOT_PORT)
        return apply_drop(skb, dst_ip, dst_port, protocol, cgroup_id, DROP_REASON_POLICY);

    /* Loopback: 127.0.0.0/8 — always allow (before allow map) */
    if ((dst_ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000))
        return 1;

    /* Link-local: 169.254.0.0/16 (metadata already caught above) */
    if ((dst_ip & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xA9FE0000))
        return 1;

    /* Deny map: operator-blocked IPs — checked before trusted_nets so deny
       overrides trust. Port=0 entry means deny all ports for that IP. */
    {
        struct allow_key deny_key = {.ip = dst_ip, .port = bpf_htons(dst_port)};
        struct allow_key deny_wild = {.ip = dst_ip, .port = 0};
        if (bpf_map_lookup_elem(&denied_ips, &deny_key) ||
            bpf_map_lookup_elem(&denied_ips, &deny_wild)) {
            /* 192.0.2.1 (RFC 5737 TEST-NET-1) is our DNS sinkhole — the
               proxy returns it for blocked A queries. A connect attempt
               means the app ignored DNS policy; tag it distinctly. */
            __u8 reason = (dst_ip == bpf_htonl(0xC0000201))
                    ? DROP_REASON_SINKHOLE : DROP_REASON_POLICY;
            return apply_drop(skb, dst_ip, dst_port, protocol, cgroup_id, reason);
        }
    }

    /* Trusted CIDRs: operator-configured networks (Docker bridge, k8s pod net) */
    struct lpm_key cidr_key = {.prefixlen = 32, .ip = dst_ip};
    if (bpf_map_lookup_elem(&trusted_nets, &cidr_key))
        return 1;

    /* --- Allow map: only checked after hard blocks --- */

    /* Check allow map */
    struct allow_key key = {.ip = dst_ip, .port = bpf_htons(dst_port)};
    if (bpf_map_lookup_elem(&allowed_ips, &key)) {
        account_bytes(skb);
        return 1; /* allowed */
    }

    /* Default deny */
    return apply_drop(skb, dst_ip, dst_port, protocol, cgroup_id, DROP_REASON_POLICY);
}

/* sock_owners is shared with the LSM hooks in sock_attr.c via cilium/ebpf
 * MapReplacements at LoadEBPF time. The split lets us load + attach the
 * LSM programs once per agent process rather than once per pod — see
 * the linuxLSMHandle singleton in platform_linux.go. */

char __license[] SEC("license") = "GPL";
