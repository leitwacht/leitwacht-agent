//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define BINARY_PATH_LEN 256

/* Minimal kernel-type declarations for the CO-RE field walks below.
 * preserve_access_index makes libbpf relocate field offsets against the
 * running kernel's BTF at load time, so the struct layouts only need
 * to match the fields we read — not vmlinux's full definitions. */
struct mm_struct {
    struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
    unsigned int flags;
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct vfsmount;
struct dentry;

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
} __attribute__((preserve_access_index));

struct sock;

struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));

struct sockaddr;
struct msghdr;

/* sock_owner is duplicated in egress.c; both .o files reference the
 * same shared sock_owners map (joined via cilium/ebpf MapReplacements).
 * The two declarations MUST stay byte-identical or the kernel rejects
 * the map-sharing at load time. The userspace BTF self-check at
 * LoadEBPF (verifyStructSize, sockOwnerSize) catches drift. */
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

/* Cgroup IDs of monitored CI job containers. Populated by userspace at
 * mgr.Attach, removed at mgr.Detach. LSM hooks run host-wide; without
 * this filter we'd allocate sk_storage for every socket on the host. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} sock_known_cgroups SEC(".maps");

/* Force clang to emit BTF for sock_owner. The userspace struct-size
 * check at LoadEBPF time depends on this surviving in the .o. */
volatile const struct sock_owner __sock_owner_btf_hint;

static __always_inline int capture_sock_owner(struct sock *sk) {
    if (!sk)
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *known = bpf_map_lookup_elem(&sock_known_cgroups, &cgroup_id);
    if (!known)
        return 0;

    struct sock_owner *o = bpf_sk_storage_get(&sock_owners, sk, NULL,
                                              BPF_SK_STORAGE_GET_F_CREATE);
    if (!o)
        return 0;

    o->cgroup_id = cgroup_id;
    o->pid = bpf_get_current_pid_tgid() >> 32;
    (void)bpf_get_current_comm(&o->comm, sizeof(o->comm));

    /* binary_path via bpf_d_path on task->mm->exe_file. Must use classic
     * (non-sleepable) lsm/* — sleepable lsm.s/* drops the BTF-typed task
     * pointer to untrusted_ptr under srcu, and bpf_d_path rejects
     * untrusted pointers ("R1 type=untrusted_ptr_..."). Verified on
     * kernel 6.19. */
    struct task_struct *task = bpf_get_current_task_btf();
    if (task && task->mm && task->mm->exe_file) {
        (void)bpf_d_path(&task->mm->exe_file->f_path,
                         o->binary_path, sizeof(o->binary_path));
    }

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(sock_attr_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!sock)
        return 0;
    return capture_sock_owner(sock->sk);
}

/* Unconnected UDP (sendto without prior connect). Once a socket has an
 * owner, return before capture_sock_owner so the (expensive)
 * bpf_d_path is not re-run on every send; the lookup without
 * F_CREATE is just a map read. The owner is written at the first
 * connect/send and kept for the socket's lifetime. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(sock_attr_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    if (!sock)
        return 0;

    /* Single load of sock->sk: re-reading the field would hand the
     * verifier a fresh or-null pointer after the NULL check. */
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;
    if (bpf_sk_storage_get(&sock_owners, sk, NULL, 0))
        return 0;
    return capture_sock_owner(sk);
}

char __license[] SEC("license") = "GPL";
