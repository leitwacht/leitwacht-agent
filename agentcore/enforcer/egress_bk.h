/* egress_bk.h — BuildKit RUN-step slot-table datapath.
 *
 * Included from egress.c ONLY when built with -DLEITWACHT_BK_MULTI (the
 * "egress_bk" object). The per-pod object never sees this file and its
 * program is unchanged.
 *
 * One program is attached at the BuildKit cgroup parent(s). For every
 * packet it finds the RUN-step cgroup (the ancestor of the packet's
 * cgroup at `bk_cfg.run_level`), looks that cgroup up in
 * bk_cgroup_policy and evaluates the packet against the policy *slot*
 * the cgroup is bound to. A slot is one rendered rule set held in three
 * inner maps (deny / static allow / DNS-derived allow); the verdict
 * (audit / shadow / block) is a property of the cgroup entry, not of a
 * global byte, and is carried in the emitted event.
 *
 * The RUN-step level is found in the kernel: bk_cfg holds the cgroup ids
 * of the BuildKit parent(s); the program scans the packet cgroup's
 * ancestors (bounded) for one of them and takes the next level down as
 * the RUN cgroup. No parent among the ancestors is DEGRADED_LEVEL (audit),
 * so a wrong cgroup layout is loud instead of silently auditing.
 *
 * A cgroup with no entry is PENDING and runs in AUDIT: the userspace
 * binder has not (yet) tied it to a project policy. Nothing here ever
 * fails closed on missing state.
 */

#define BK_STATE_PENDING      0 /* no entry: not bound yet */
#define BK_STATE_BOUND        1 /* bound to a slot */
#define BK_STATE_AMBIGUOUS    2 /* candidates span projects: audit */
#define BK_STATE_UNATTRIBUTED 3 /* no usable attribution: audit */
#define BK_STATE_DEGRADED     4 /* capacity/history/policy trouble: audit */
#define BK_STATE_DEGRADED_LEVEL 5 /* no configured parent found among the packet's ancestors: audit */

#define BK_MODE_AUDIT  0
#define BK_MODE_SHADOW 1
#define BK_MODE_BLOCK  2

#define BK_VERDICT_DROPPED     1
#define BK_VERDICT_OBSERVED    2
#define BK_VERDICT_WOULD_BLOCK 3
#define BK_VERDICT_ALLOWED     4
#define BK_VERDICT_HELD        5 /* TCP SYN dropped by the pre-bind hold */

/* bk_cfg.flags bits. */
#define BK_CFG_HOLD_ENABLED 1 /* hold SYNs of PENDING cgroups (userspace sets it only while an enforce policy exists) */

#define BK_MAX_SLOTS 256
#define BK_MAX_PARENTS 8
#define BK_MAX_DNS 4
#define BK_MAX_LEVEL 16

#define DROP_REASON_DNS_BYPASS 3
#define DROP_REASON_IPV6       4

/* Dedup windows. Deny/observe events collapse retransmits of one
   connection (1 s, as in the per-pod object); allowed connections are
   recorded at most once per minute per (ip, port, cgroup) so build
   egress stays visible without a row per connection. */
#define BK_DENY_DEDUP_NS  1000000000ULL
#define BK_ALLOW_DEDUP_NS 60000000000ULL

/* The map value carries a spin lock: userspace replaces entries in place
   with BPF_F_LOCK and the program copies the value out under the lock, so
   slot/state/mode/gen are always read as one consistent tuple. */
struct bk_cg_val {
    struct bpf_spin_lock lock;
    __u32 slot;
    __u8  state;
    __u8  mode;
    __u16 flags;
    __u32 gen;
};

/* Lock-free working copy used by the program. */
struct bk_cur {
    __u32 slot;
    __u8  state;
    __u8  mode;
    __u16 flags;
    __u32 gen;
};

struct bk_cfg_val {
    __u32 run_level; /* nonzero: fixed RUN level (tests); 0: scan for parents */
    __u32 n_parents;
    __u32 n_dns;
    __u32 flags;
    __u64 hold_ns; /* SYN-hold window; 0 = never hold */
    __u64 parents[BK_MAX_PARENTS]; /* cgroup ids of the BuildKit parents */
    __u32 dns_ip[BK_MAX_DNS];      /* DNS upstreams (network order) for the port-53 pin */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct bk_cg_val);
    __uint(max_entries, 16384);
} bk_cgroup_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bk_cfg_val);
    __uint(max_entries, 1);
} bk_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, BK_MAX_SLOTS);
    __type(key, __u32);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, struct allow_key);
        __type(value, __u32);
    });
} bk_deny_sets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, BK_MAX_SLOTS);
    __type(key, __u32);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, struct allow_key);
        __type(value, __u32);
    });
} bk_host_sets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, BK_MAX_SLOTS);
    __type(key, __u32);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 8192);
        __type(key, struct allow_key);
        __type(value, __u32);
    });
} bk_dns_sets SEC(".maps");

/* First time a PENDING RUN cgroup was seen sending a holdable SYN
   (cgroup id -> ktime). The hold window is measured from here, so a
   held SYN can never stall past it. An LRU eviction only restarts the
   window of a cgroup that is still unbound; the joiner deadline writes
   a non-PENDING entry (which ends holding) within the same window. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 4096);
} bk_pending_since SEC(".maps");

/* 60 s dedup for packet_allowed events. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct dedup_key);
    __type(value, __u64);
    __uint(max_entries, 8192);
} bk_allow_dedup SEC(".maps");

/* Same variable-liveness trick as the per-pod hints. allow_key needs one
   too: it is otherwise only reached through pointers inside the inner-map
   templates, which clang then emits as a forward declaration (unsized). */
volatile const struct bk_cg_val __bk_cg_val_btf_hint;
volatile const struct allow_key __bk_allow_key_btf_hint;

/* FOLD_PRIO over an inner map reached through a pointer (the map
   argument is a pointer value, not a literal, so the per-pod macro that
   takes the address of a named map cannot be reused). */
#define BK_FOLD_PRIO(mp, ip_, port_, best)                              \
    do {                                                               \
        struct allow_key _k = {.ip = (ip_), .port = (port_)};          \
        __u32 *_v = bpf_map_lookup_elem((mp), &_k);                    \
        if (_v && *_v < (best))                                        \
            (best) = *_v;                                              \
        _k.port = 0;                                                   \
        _v = bpf_map_lookup_elem((mp), &_k);                           \
        if (_v && *_v < (best))                                        \
            (best) = *_v;                                              \
    } while (0)

struct bk_ev_args {
    __u32 ip;
    __u16 port;
    __u8  proto;
    __u8  reason;
    __u8  verdict;
};

/* A BPF-to-BPF call (not inlined): it is reached from a dozen verdict
   sites and inlining it at each of them multiplied the program size. */
static __noinline void bk_emit_event(struct __sk_buff *skb,
                                     const struct bk_ev_args *a,
                                     const struct bk_cur *bk) {
    struct dedup_key dedup_key = {.ip = a->ip, .port = a->port, .cgroup_id = bpf_skb_cgroup_id(skb)};
    __u64 now = bpf_ktime_get_ns();
    __u64 window = BK_DENY_DEDUP_NS;
    __u64 *last;

    if (a->verdict == BK_VERDICT_ALLOWED) {
        window = BK_ALLOW_DEDUP_NS;
        last = bpf_map_lookup_elem(&bk_allow_dedup, &dedup_key);
    } else {
        last = bpf_map_lookup_elem(&drop_dedup, &dedup_key);
    }

    if (last && (now - *last) < window)
        return;

    /* Attribution comes from sk_storage exactly as in the per-pod
       object (see emit_drop_event in egress.c for why). */
    struct sock_owner *owner = NULL;
    if (skb && skb->sk)
        owner = bpf_sk_storage_get(&sock_owners, skb->sk, NULL, 0);
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

    __builtin_memset(ev, 0, sizeof(*ev));

    ev->dst_ip = a->ip;
    ev->dst_port = a->port;
    ev->protocol = a->proto;
    ev->reason = a->reason;
    ev->cgroup_id = owner->cgroup_id;
    ev->pid = owner->pid;
    __builtin_memcpy(&ev->comm, &owner->comm, sizeof(ev->comm));
    __builtin_memcpy(&ev->binary_path, &owner->binary_path, sizeof(ev->binary_path));
    ev->verdict = a->verdict;
    ev->state = bk->state;
    ev->slot = bk->slot;
    ev->gen = bk->gen;

    bpf_ringbuf_submit(ev, 0);

    if (a->verdict == BK_VERDICT_ALLOWED)
        (void)bpf_map_update_elem(&bk_allow_dedup, &dedup_key, &now, BPF_ANY);
    else
        (void)bpf_map_update_elem(&drop_dedup, &dedup_key, &now, BPF_ANY);
}

static __always_inline void bk_emit(struct __sk_buff *skb, __u32 ip, __u16 port, __u8 proto,
                                    __u8 reason, __u8 verdict, const struct bk_cur *bk) {
    struct bk_ev_args a = {.ip = ip, .port = port, .proto = proto, .reason = reason, .verdict = verdict};

    bk_emit_event(skb, &a, bk);
}

/* Verdict for a packet that policy (or an invariant) says to deny:
   the cgroup's mode decides whether it is dropped, passed with a
   would-block record, or passed with an observation. */
static __always_inline int bk_deny(struct __sk_buff *skb, __u32 ip, __u16 port,
                                   __u8 proto, __u8 reason,
                                   const struct bk_cur *bk) {
    if (bk->mode == BK_MODE_BLOCK) {
        bk_emit(skb, ip, port, proto, reason, BK_VERDICT_DROPPED, bk);
        return 0;
    }

    bk_emit(skb, ip, port, proto,
            reason,
            bk->mode == BK_MODE_SHADOW ? BK_VERDICT_WOULD_BLOCK : BK_VERDICT_OBSERVED,
            bk);
    account_bytes(skb);
    return 1;
}

/* Cloud metadata endpoints: a hard block for every cgroup state. */
static __always_inline int bk_meta_ip(__u32 ip) {
    return ip == bpf_htonl(0xA9FEA9FE) ||
           ip == bpf_htonl(0xA9FEAA02) ||
           ip == bpf_htonl(0xA9FEAA17) ||
           ip == bpf_htonl(0x646464C8) ||
           ip == bpf_htonl(0xA9FE0017);
}

/* Destinations the hold must never exempt (trusted nets, DNS upstreams):
   metadata, DoT on any IP, the DNS sinkhole. */
static __always_inline int bk_hard_dst(__u32 ip, __u16 port) {
    return bk_meta_ip(ip) || port == DOT_PORT || ip == bpf_htonl(0xC0000201);
}

/* Pre-bind SYN hold. A PENDING RUN cgroup has no policy entry yet (the
   join takes 25-50 ms), so a connect in that window would pass
   un-enforced. While hold is enabled and the cgroup is younger than the
   hold window, its TCP SYNs are dropped (event verdict HELD): the
   kernel's retransmit (about 1 s later) is judged by the slot once the
   cgroup is bound. It runs BEFORE the hard blocks and the IPv6 branch,
   so metadata/DoT/IPv6 SYNs cannot slip through the window either. The
   caller exempts trusted nets, loopback and DNS upstreams. After the
   window the cgroup is audit (pass + record): never fail-closed. Only
   state PENDING is held; ambiguous/unattributed/degraded cgroups carry
   an entry and are audit. Returns 1 when the SYN was held. */
static __noinline int bk_hold_syn(struct __sk_buff *skb, __u64 run_id, const struct bk_ev_args *a,
                                  const struct bk_cur *bk) {
    __u32 zero = 0;
    struct bk_cfg_val *cfg = bpf_map_lookup_elem(&bk_cfg, &zero);

    if (!cfg || !cfg->hold_ns)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 first = now;
    __u64 *since = bpf_map_lookup_elem(&bk_pending_since, &run_id);

    if (since)
        first = *since;
    else
        (void)bpf_map_update_elem(&bk_pending_since, &run_id, &now, BPF_NOEXIST);

    if (now - first >= cfg->hold_ns)
        return 0;

    bk_emit_event(skb, a, bk);

    return 1;
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct bk_cfg_val *cfg = bpf_map_lookup_elem(&bk_cfg, &zero);
    __u64 run_id = 0;
    int found = 0;

    struct bk_cur bk = {.slot = 0, .state = BK_STATE_PENDING, .mode = BK_MODE_AUDIT, .flags = 0, .gen = 0};

    /* Find the RUN-step cgroup: the child of the BuildKit parent among
       the packet cgroup's ancestors. A packet from the parent itself
       finds the parent but no child (run_id 0): PENDING/audit. */
    if (cfg) {
        if (cfg->run_level) {
            run_id = bpf_skb_ancestor_cgroup_id(skb, cfg->run_level);
            found = 1;
        } else if (cfg->n_parents) {
#pragma unroll
            for (int l = 0; l < BK_MAX_LEVEL; l++) {
                if (found)
                    break;

                __u64 a = bpf_skb_ancestor_cgroup_id(skb, l);
                if (!a)
                    break;

#pragma unroll
                for (int p = 0; p < BK_MAX_PARENTS; p++) {
                    if (p >= cfg->n_parents)
                        break;
                    if (a == cfg->parents[p]) {
                        found = 1;
                        run_id = bpf_skb_ancestor_cgroup_id(skb, l + 1);
                        break;
                    }
                }
            }

            if (!found)
                bk.state = BK_STATE_DEGRADED_LEVEL;
        }
    }

    if (run_id) {
        struct bk_cg_val *pv = bpf_map_lookup_elem(&bk_cgroup_policy, &run_id);
        if (pv) {
            /* One consistent tuple: copy out under the lock, then use
               the copy. Nothing else runs inside the critical section. */
            bpf_spin_lock(&pv->lock);
            bk.slot = pv->slot;
            bk.state = pv->state;
            bk.mode = pv->mode;
            bk.flags = pv->flags;
            bk.gen = pv->gen;
            bpf_spin_unlock(&pv->lock);
        }
    }

    /* Only a BOUND cgroup is ever shadowed or blocked. */
    if (bk.state != BK_STATE_BOUND)
        bk.mode = BK_MODE_AUDIT;

    __u8 ver_ihl;
    if (bpf_skb_load_bytes(skb, 0, &ver_ihl, 1) < 0)
        return 1;

    __u8 version = ver_ihl >> 4;

    if (version == 6) {
        struct in6_addr daddr;
        if (bpf_skb_load_bytes(skb, 24, &daddr, sizeof(daddr)) < 0)
            return 1;

        if (daddr.in6_u.u6_addr32[0] == 0 &&
            daddr.in6_u.u6_addr32[1] == 0 &&
            daddr.in6_u.u6_addr32[2] == 0 &&
            daddr.in6_u.u6_addr32[3] == bpf_htonl(1))
            return 1; /* loopback */

        /* Pre-bind hold for IPv6 TCP SYNs (only ::1 is exempt). */
        if (bk.state == BK_STATE_PENDING && run_id && cfg && (cfg->flags & BK_CFG_HOLD_ENABLED) && cfg->hold_ns) {
            __u8 nh6 = 0;
            __u8 fl6 = 0;
            __be16 dp6;

            if (bpf_skb_load_bytes(skb, 6, &nh6, 1) == 0 && nh6 == IPPROTO_TCP &&
                bpf_skb_load_bytes(skb, 53, &fl6, 1) == 0 && (fl6 & 0x12) == 0x02 &&
                bpf_skb_load_bytes(skb, 42, &dp6, sizeof(dp6)) == 0 &&
                bk_hold_syn(skb, run_id, &(struct bk_ev_args){.ip = 0, .port = bpf_ntohs(dp6), .proto = IPPROTO_TCP,
                                                              .reason = DROP_REASON_IPV6, .verdict = BK_VERDICT_HELD}, &bk))
                return 0;
        }

        /* IPv6 is not supported by the policy maps: a BOUND cgroup in
           BLOCK drops it, in SHADOW records would_block, in audit it
           passes unrecorded (as in the per-pod object). The event
           carries ip 0 (a 4-byte field cannot name the address) and the
           destination port, reason IPV6. */
        if (bk.mode != BK_MODE_AUDIT) {
            __u8 nh = 0;
            __u16 p6 = 0;

            if (bpf_skb_load_bytes(skb, 6, &nh, 1) == 0 &&
                (nh == IPPROTO_TCP || nh == IPPROTO_UDP)) {
                __be16 d6;
                if (bpf_skb_load_bytes(skb, 42, &d6, sizeof(d6)) == 0)
                    p6 = bpf_ntohs(d6);
            }

            return bk_deny(skb, 0, p6, nh, DROP_REASON_IPV6, &bk);
        }

        account_bytes(skb);
        return 1;
    }

    if (version != 4)
        return 1;

    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
        return 1;

    __u32 dst_ip = iph.daddr;
    __u8 protocol = iph.protocol;
    __u32 ip_hlen = iph.ihl * 4;
    __u16 dst_port = 0;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __be16 dport;
        if (bpf_skb_load_bytes(skb, ip_hlen + 2, &dport, sizeof(dport)) < 0)
            return 1;
        dst_port = bpf_ntohs(dport);
    }

    /* --- Pre-bind SYN hold: first, so hard-blocked destinations (metadata,
       DoT, sinkhole) cannot escape during the pre-bind window. Exempt:
       loopback, trusted nets, DNS upstreams. --- */
    if (bk.state == BK_STATE_PENDING && run_id && cfg && (cfg->flags & BK_CFG_HOLD_ENABLED) && cfg->hold_ns && protocol == IPPROTO_TCP &&
        (dst_ip & bpf_htonl(0xFF000000)) != bpf_htonl(0x7F000000)) {
        __u8 tcp_flags = 0;

        if (bpf_skb_load_bytes(skb, ip_hlen + 13, &tcp_flags, 1) == 0 && (tcp_flags & 0x12) == 0x02) {
            int exempt = 0;
            struct lpm_key hold_ck = {.prefixlen = 32, .ip = dst_ip};

            if (bpf_map_lookup_elem(&trusted_nets, &hold_ck))
                exempt = 1;

#pragma unroll
            for (int i = 0; i < BK_MAX_DNS; i++) {
                if (i >= cfg->n_dns)
                    break;
                if (cfg->dns_ip[i] == dst_ip)
                    exempt = 1;
            }

            struct bk_ev_args hold_a = {.ip = dst_ip, .port = dst_port, .proto = IPPROTO_TCP,
                                        .reason = DROP_REASON_POLICY, .verdict = BK_VERDICT_HELD};

            if (bk_hard_dst(dst_ip, dst_port))
                exempt = 0;

            if (!exempt && bk_hold_syn(skb, run_id, &hold_a, &bk))
                return 0;
        }
    }

    /* --- Hard blocks: invariants, checked before any rule. --- */
    if (bk_meta_ip(dst_ip))
        return bk_deny(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY, &bk);

    if (dst_port == DOT_PORT)
        return bk_deny(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY, &bk);

    /* 192.0.2.1 is the DNS sinkhole: a connect means the app ignored
       DNS policy. Hard-coded here so no slot needs seeding with it. */
    if (dst_ip == bpf_htonl(0xC0000201))
        return bk_deny(skb, dst_ip, dst_port, protocol, DROP_REASON_SINKHOLE, &bk);

    if ((dst_ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000))
        return 1;

    if ((dst_ip & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xA9FE0000))
        return 1;

    __u16 dport_be = bpf_htons(dst_port);

    /* --- DNS pin (SHADOW/BLOCK): port 53 only to the configured DNS
       upstream(s), whatever the rules or trusted networks say, so a RUN
       step cannot tunnel through (or pick) another resolver. Disabled
       when no upstream is configured. Evaluated before trusted_nets. --- */
    if (bk.mode != BK_MODE_AUDIT && dst_port == 53 &&
        (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) && cfg && cfg->n_dns) {
        int dns_ok = 0;

#pragma unroll
        for (int i = 0; i < BK_MAX_DNS; i++) {
            if (i >= cfg->n_dns)
                break;
            if (cfg->dns_ip[i] == dst_ip)
                dns_ok = 1;
        }

        if (!dns_ok)
            return bk_deny(skb, dst_ip, dst_port, protocol, DROP_REASON_DNS_BYPASS, &bk);

        bk_emit(skb, dst_ip, dst_port, protocol, 0, BK_VERDICT_ALLOWED, &bk);
        account_bytes(skb);
        return 1;
    }

    /* --- Slot rules (only for a BOUND cgroup). --- */

    if (bk.state == BK_STATE_BOUND) {
        __u32 slot = bk.slot;
        void *deny = bpf_map_lookup_elem(&bk_deny_sets, &slot);
        void *host = bpf_map_lookup_elem(&bk_host_sets, &slot);
        void *dns = bpf_map_lookup_elem(&bk_dns_sets, &slot);

        if (deny && host && dns) {
            __u32 deny_prio = PRIO_NONE;
            __u32 allow_prio = PRIO_NONE;

            BK_FOLD_PRIO(deny, dst_ip, dport_be, deny_prio);
            BK_FOLD_PRIO(host, dst_ip, dport_be, allow_prio);

            {
                struct allow_key dns_key = {.ip = dst_ip, .port = dport_be};
                __u32 *dns_prio = bpf_map_lookup_elem(dns, &dns_key);
                if (dns_prio && *dns_prio < allow_prio)
                    allow_prio = *dns_prio;
            }

            if (deny_prio != PRIO_NONE && deny_prio <= allow_prio)
                return bk_deny(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY, &bk);

            if (allow_prio != PRIO_NONE) {
                bk_emit(skb, dst_ip, dst_port, protocol, 0, BK_VERDICT_ALLOWED, &bk);
                account_bytes(skb);
                return 1;
            }
        } else {
            /* A BOUND entry whose slot maps are gone must not drop
               anything: treat it as audit and say so. */
            bk.mode = BK_MODE_AUDIT;
            bk.state = BK_STATE_DEGRADED;
        }
    }

    struct lpm_key cidr_key = {.prefixlen = 32, .ip = dst_ip};
    if (bpf_map_lookup_elem(&trusted_nets, &cidr_key))
        return 1;

    /* Default deny: BLOCK drops, SHADOW records would_block, everything
       else (audit, pending, ambiguous, unattributed, degraded) observes. */
    return bk_deny(skb, dst_ip, dst_port, protocol, DROP_REASON_POLICY, &bk);
}
