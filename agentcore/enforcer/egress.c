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

/* Rule priority. The IP-policy maps store, as their value, the index of
   the rule that produced the entry in the job's composed rule list —
   so the datapath can reproduce the list's first-match-wins semantics
   instead of hardcoding "deny beats allow". Lower wins.

   Priority 0 is reserved for system-seeded entries that hold no
   position in any rule list and must beat every rule: the DNS sinkhole
   deny, and CE's standalone `deny_ips:` blocklist. Rule-derived entries
   start at 1.

   PRIO_NONE is the "no entry" sentinel — it must stay larger than any
   real rule index, which is guaranteed since composed lists are many
   orders of magnitude shorter than 2^32. */
#define PRIO_NONE 0xFFFFFFFFU

/* Fold a map hit into the running best (lowest) priority. Checks the
   exact {ip, port} key then the port=0 wildcard, which means "any port
   on this IP". Written as a macro rather than a helper taking void*:
   the map argument has to be a literal for the verifier to resolve it,
   and this keeps that obvious at each call site. */
#define FOLD_PRIO(m, ip_, port_, best)                                  \
    do {                                                               \
        struct allow_key _k = {.ip = (ip_), .port = (port_)};          \
        __u32 *_v = bpf_map_lookup_elem(&(m), &_k);                    \
        if (_v && *_v < (best))                                        \
            (best) = *_v;                                              \
        _k.port = 0;                                                   \
        _v = bpf_map_lookup_elem(&(m), &_k);                           \
        if (_v && *_v < (best))                                        \
            (best) = *_v;                                              \
    } while (0)

/* struct sock is opaque; only used as a handle for bpf_sk_storage_get. */
struct sock;

struct allow_key {
    __u32 ip;
    __u16 port;
} __attribute__((packed));

/* DNS-derived allows. Seeded by the DNS proxy when a query matches an
   allow rule and resolves; the value is that rule's priority, so a
   deny rule sitting above it in the list still wins.

   LRU is correct here and only here: entries are re-seeded on every
   re-resolution, so eviction costs at most one extra DNS round trip.
   Statically-seeded entries must NOT live in this map — see
   allowed_hosts. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct allow_key);
    __type(value, __u32);
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

/* Per-packet violation attribution. All identity fields are sourced
   from sk_storage, captured by the LSM socket hooks (sock_attr.c) in
   process context. The cgroup_skb/egress program itself calls no
   current-task helpers (see emit_drop_event), so attribution is
   correct regardless of whether the packet is emitted in process or
   softirq context — and the program loads on cgroup_skb proto tables
   from 5.10 through 6.18+. */
struct drop_event {
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;
    __u64 cgroup_id;        /* socket creator's cgroup (from sk_storage) */
    __u8  reason;           /* DROP_REASON_* */
    __u32 pid;              /* tgid of connecting task (from sk_storage) */
    char  comm[16];         /* process name */
    char  binary_path[BINARY_PATH_LEN]; /* bpf_d_path result from LSM capture */
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

/* Operator-denied IPs. Value is the denying rule's priority; port=0
   means deny all ports for that IP.

   Plain HASH, not an LRU: these entries (including the priority-0
   sinkhole and CE deny_ips) are seeded once and never re-seeded, so
   an LRU would silently evict a deny and turn it into an allow.
   A full map makes the userspace Put fail with E2BIG instead. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct allow_key);
    __type(value, __u32);
    __uint(max_entries, 4096);
} denied_ips SEC(".maps");

/* Count of drop-event ringbuf reserve failures (ring full). Drop events
   are evidence only; the verdict does not depend on them, but a full
   ring loses them silently, so userspace reads this counter. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} reserve_failures SEC(".maps");

/* Operator-allowed IPs — the static counterpart to allowed_ips, for
   destinations that have no DNS name at all (deploy targets, ClusterIPs,
   hard-coded registry addresses). Populated at attach from the job's
   composed cidr+allow rules; value is the rule's priority, port=0 means
   any port on that IP.

   Deliberately a plain HASH, not an LRU: nothing re-seeds these entries
   after attach, so an eviction would silently turn a permitted
   destination into an intermittent, unreproducible drop. Bounded size
   is the right failure mode here — a full map fails loudly at install
   time instead of quietly at 3am. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct allow_key);
    __type(value, __u32);
    __uint(max_entries, 4096);
} allowed_hosts SEC(".maps");

/* Per-socket attribution.
 *
 * Populated by LSM hooks (socket_connect, socket_sendmsg)
 * that always run in process context — current is guaranteed to be the
 * real socket owner. Read from cgroup_skb/egress where, in softirq
 * context (TCP retransmits, keepalives, delayed ACKs), current is
 * whichever task got preempted on that CPU and would misattribute.
 *
 * No socket_accept hook: accepted sockets get sk_storage at the
 * first sendmsg (the server calling send on the accepted socket).
 * Without an sk_storage owner, emit_drop_event drops the event
 * entirely, so softirq traffic (ACKs, keepalives) on not-yet-captured
 * accepted sockets produces no noise. Adding socket_accept would
 * create sk_storage entries that publish events for accepted sockets.
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

static __always_inline void emit_drop_event(struct __sk_buff *skb,
                                            __u32 ip, __u16 port, __u8 proto,
                                            __u8 reason) {
    /* Dedup first: 1-second window on (ip, port). Runs before the
     * sk_storage lookup so we don't pay it on the ~99% of events that
     * are retransmits of an already-published drop on a failed
     * connection. */
    struct allow_key dedup_key = {.ip = ip, .port = port};
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&drop_dedup, &dedup_key);

    if (last && (now - *last) < 1000000000ULL) /* 1 second */
        return;

    /* Attribution comes EXCLUSIVELY from sk_storage, captured at LSM
     * socket_connect / sendmsg (sock_attr.c) — always in process
     * context, so pid/comm/binary_path are authoritative and immune
     * to softirq context where `current` is the preempted task.
     *
     * We deliberately do NOT fall back to bpf_get_current_* here:
     * those helpers aren't exposed to cgroup_skb on kernels < 6.18
     * (cg_skb_func_proto has socket/skb helpers only), so using them
     * makes the whole egress program fail the verifier on 6.1 — the
     * kernel we need for Firecracker snapshot/restore. Dropping the
     * fallback keeps one program that loads from 5.10 through 6.18+.
     *
     * Consequence: a packet with no sk_storage owner (socket created
     * before the agent attached, or skb->sk NULL) is not published.
     * In every supported deployment the agent attaches before the
     * workload runs and the LSM socket hooks are loaded, so the owner
     * is populated on effectively every socket — the no-owner path is
     * the pre-attach-race canary the integration tests already treat
     * as anomalous, not a steady-state source of events.
     *
     * skb->sk is a trusted bpf_sock in cgroup_skb/egress;
     * bpf_sk_storage_get's arg2 accepts ARG_PTR_TO_SOCK_COMMON (bpf_sock
     * satisfies), so pass it directly with no cast to preserve the
     * verifier's trust relation. */
    struct sock_owner *owner = NULL;
    if (skb && skb->sk) {
        owner = bpf_sk_storage_get(&sock_owners, skb->sk, NULL, 0);
    }
    if (!owner)
        return;

    struct drop_event *ev = bpf_ringbuf_reserve(&drop_events, sizeof(struct drop_event), 0);
    if (!ev) {
        __u32 zero = 0;
        __u64 *fails = bpf_map_lookup_elem(&reserve_failures, &zero);

        if (fails)
            *fails += 1;
        return;
    }

    /* Ringbuf reserve returns uninitialised slot memory — zero the
     * whole struct so stale bytes from a prior event can't leak into
     * fields we don't write. */
    __builtin_memset(ev, 0, sizeof(*ev));

    ev->dst_ip = ip;
    ev->dst_port = port;
    ev->protocol = proto;
    ev->reason = reason;

    /* Authoritative attribution from LSM capture. Use the owner's
     * cgroup_id rather than the skb's: on softirq-origin packets the
     * skb cgroup is correct too, but the userspace recorder lookup
     * keys on the socket creator's cgroup, which is what owner holds. */
    ev->cgroup_id = owner->cgroup_id;
    ev->pid = owner->pid;
    __builtin_memcpy(&ev->comm, &owner->comm, sizeof(ev->comm));
    __builtin_memcpy(&ev->binary_path, &owner->binary_path,
                     sizeof(ev->binary_path));

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
                                      __u8 reason) {
    emit_drop_event(skb, ip, port, proto, reason);

    if (get_mode() == 1) {
        account_bytes(skb);
        return 1; /* audit: allow but record */
    }

    return 0; /* block: drop */
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    /* Use bpf_skb_load_bytes for cgroup_skb — direct packet access is
       unreliable across kernel versions for this program type.

       Note: this program intentionally calls NO cgroup/current-task
       helpers. Attribution is sourced entirely from sk_storage
       (populated by the LSM socket hooks in sock_attr.c). That keeps
       cg_skb_func_proto happy on kernels from 5.10 through 6.18+ —
       older cgroup_skb proto tables expose socket/skb helpers only,
       not bpf_get_current_* — which is what lets the agent load on
       the 6.1 kernel the Firecracker snapshot path requires. */

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

    /* Extract destination port for TCP/UDP.
     *
     * bpf_skb_load_bytes failure (return 1 = allow) is not a bypass:
     * locally-originated packets pass cgroup_skb/egress before
     * ip_fragment(), so transport headers are always present. Raw
     * sockets with IP_HDRINCL cannot fragment (kernel forbids it per
     * raw(7)), and without IP_HDRINCL the kernel fragments after this
     * hook. AF_PACKET bypasses cgroup_skb entirely. The failure path
     * is only reachable on corrupt/malformed skbs. */
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        /* Destination port is at offset 2 in both TCP and UDP headers */
        __be16 dport;
        if (bpf_skb_load_bytes(skb, ip_hlen + 2, &dport, sizeof(dport)) < 0)
            return 1;
        dst_port = bpf_ntohs(dport);
    }

    /* --- Hard blocks: checked BEFORE the allow map so DNS rebinding can't bypass them --- */

    /* Cloud metadata / workload-credential endpoints — always block
       regardless of allow map. Prevents DNS rebinding attacks (attacker
       domain resolving to one of these IPs):
         169.254.169.254  AWS/GCP/Azure/etc. instance metadata
         169.254.170.2    ECS task role credentials
         169.254.170.23   EKS Pod Identity agent
         100.100.100.200  Alibaba Cloud metadata
         169.254.0.23     Tencent Cloud metadata
       IPv6 (e.g. fd00:ec2::254) needs no entry: all non-loopback IPv6
       is dropped above in block mode. */
    if (dst_ip == bpf_htonl(0xA9FEA9FE) ||
        dst_ip == bpf_htonl(0xA9FEAA02) ||
        dst_ip == bpf_htonl(0xA9FEAA17) ||
        dst_ip == bpf_htonl(0x646464C8) ||
        dst_ip == bpf_htonl(0xA9FE0017))
        return apply_drop(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY);

    /* DoT: always block port 853 */
    if (dst_port == DOT_PORT)
        return apply_drop(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY);

    /* Loopback: 127.0.0.0/8 — always allow (before allow map) */
    if ((dst_ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000))
        return 1;

    /* Link-local: 169.254.0.0/16 (known metadata/credential endpoints
       already caught above) */
    if ((dst_ip & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xA9FE0000))
        return 1;

    /* --- Ordered rule evaluation: lowest priority wins --------------
     *
     * Each IP-policy map stores the priority of the rule that produced
     * the entry, so the winner here is whichever rule appears first in
     * the job's composed list — the same first-match-wins semantics the
     * DNS proxy applies to fqdn rules, and what an operator expects
     * from a firewall ruleset.
     *
     * The hard blocks above are deliberately NOT part of this
     * evaluation: cloud metadata, DoT and the loopback / link-local
     * carve-outs are invariants, not policy, and no rule ordering may
     * reach them. */
    __u16 dport_be = bpf_htons(dst_port);
    __u32 deny_prio = PRIO_NONE;
    __u32 allow_prio = PRIO_NONE;

    FOLD_PRIO(denied_ips, dst_ip, dport_be, deny_prio);
    FOLD_PRIO(allowed_hosts, dst_ip, dport_be, allow_prio);

    /* DNS-derived allows are seeded per resolved {ip, port} and have no
       any-port form, so no wildcard probe here. */
    {
        struct allow_key dns_key = {.ip = dst_ip, .port = dport_be};
        __u32 *dns_prio = bpf_map_lookup_elem(&allowed_ips, &dns_key);
        if (dns_prio && *dns_prio < allow_prio)
            allow_prio = *dns_prio;
    }

    /* Ties go to deny. Distinct rules can't share an index, so a tie
       only arises between system-seeded (priority 0) entries. */
    if (deny_prio != PRIO_NONE && deny_prio <= allow_prio) {
        /* 192.0.2.1 (RFC 5737 TEST-NET-1) is our DNS sinkhole — the
           proxy returns it for blocked A queries. A connect attempt
           means the app ignored DNS policy; tag it distinctly. */
        __u8 reason = (dst_ip == bpf_htonl(0xC0000201))
                ? DROP_REASON_SINKHOLE : DROP_REASON_POLICY;
        return apply_drop(skb, dst_ip, dst_port, protocol, reason);
    }

    if (allow_prio != PRIO_NONE) {
        account_bytes(skb);
        return 1; /* allowed */
    }

    /* Trusted CIDRs: node-level operator config (Docker bridge, k8s pod
       net). These hold no position in any rule list, so they are
       consulted only once every rule has missed — an explicit deny rule
       still overrides trust, as it did before ordering existed. */
    struct lpm_key cidr_key = {.prefixlen = 32, .ip = dst_ip};
    if (bpf_map_lookup_elem(&trusted_nets, &cidr_key))
        return 1;

    /* Default deny */
    return apply_drop(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY);
}

/* sock_owners is shared with the LSM hooks in sock_attr.c via cilium/ebpf
 * MapReplacements at LoadEBPF time. The split lets us load + attach the
 * LSM programs once per agent process rather than once per pod — see
 * the linuxLSMHandle singleton in platform_linux.go. */

char __license[] SEC("license") = "GPL";
