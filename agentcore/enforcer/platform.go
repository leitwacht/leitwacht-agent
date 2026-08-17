package enforcer

import (
	"context"
	"net"
	"sync/atomic"
)

// Platform abstracts the privileged OS operations needed for enforcement.
// The production implementation uses eBPF, netns, and nftables (requires root + Linux).
// Tests inject a fake to verify orchestration logic without privileges.
type Platform interface {
	// GetCgroupPath returns the cgroupv2 filesystem path for a container PID.
	GetCgroupPath(pid int) (string, error)

	// NetnsInode returns the inode of /proc/<pid>/ns/net, which uniquely
	// identifies the network namespace. Containers in the same Kubernetes pod
	// share a netns and therefore return the same inode — used to dedupe
	// enforcement attempts so the second container in a pod doesn't collide
	// on the DNS proxy bind.
	NetnsInode(pid int) (uint64, error)

	// BindInNetns creates UDP and TCP listeners on listenAddr inside the
	// network namespace of the given PID. The returned connections remain
	// valid after the namespace is exited.
	BindInNetns(pid int, listenAddr string) (net.PacketConn, net.Listener, error)

	// SetupDNSRedirect installs nftables rules inside the container's netns
	// to redirect outbound DNS (port 53) to the proxy port.
	SetupDNSRedirect(pid int) error

	// RemoveDNSRedirect removes the nftables redirect rules. Best-effort:
	// returns nil even if the netns is already gone.
	RemoveDNSRedirect(pid int) error

	// LoadEBPF loads the eBPF egress filter program and maps.
	// The program is NOT attached to a cgroup here — use EBPFHandle.AttachCgroup
	// to attach to individual container cgroups.
	// trustedCIDRs are populated in the LPM trie — traffic to these networks
	// is allowed without DNS resolution (e.g. Docker bridge, k8s pod network).
	LoadEBPF(auditMode bool, trustedCIDRs []net.IPNet) (EBPFHandle, error)

	// CgroupID returns the inode number of a cgroup directory,
	// which matches what bpf_get_current_cgroup_id() returns.
	CgroupID(cgroupPath string) (uint64, error)

	// DialUpstreamInNetns creates a UDP connection to addr inside the
	// container's netns, marked with SO_MARK to bypass nftables redirect.
	// Used for Docker DNS chaining. Returns nil, nil when not needed.
	DialUpstreamInNetns(pid int, addr string, mark int) (*net.UDPConn, error)
}

// EBPFHandle represents a loaded eBPF program with its maps.
type EBPFHandle interface {
	// AddAllowedIP adds an {ip, port} pair to the DNS-derived allow map.
	// prio is the priority of the fqdn rule that authorised the
	// resolution — see RulePriority.
	AddAllowedIP(ip net.IP, ports []int, prio uint32) error

	// AddAllowedHost adds an {ip, port} pair to the static allow map,
	// for destinations that have no DNS name. Port 0 means allow all
	// ports for this IP. prio is the allowing rule's priority.
	//
	// Distinct from AddAllowedIP: these entries are never re-seeded, so
	// they live in a non-LRU map that cannot silently evict them.
	AddAllowedHost(ip net.IP, port int, prio uint32) error

	// RemoveAllowedHost deletes an {ip, port} entry from the static
	// allow map. Idempotent: missing entries are not an error.
	RemoveAllowedHost(ip net.IP, port int) error

	// FlushAllowedIPs empties the DNS-derived allow map.
	//
	// Those entries have no per-container owner — the DNS proxy serves
	// the whole netns and doesn't know which container asked — so they
	// can't be reversed at Detach the way deny and static-allow entries
	// are. Called when the last container leaves the netns, before the
	// grace period during which a different job may join and reuse
	// these maps.
	FlushAllowedIPs() error

	// AddDeniedIP adds an IP (with optional port) to the deny map.
	// Port 0 means deny all ports for this IP. prio is the denying
	// rule's priority.
	AddDeniedIP(ip net.IP, port int, prio uint32) error

	// RemoveDeniedIP deletes an {ip, port} entry from the deny map.
	// Idempotent: missing entries are not an error.
	RemoveDeniedIP(ip net.IP, port int) error

	// ReadStats returns total bytes counted by the eBPF stats map.
	ReadStats() int64

	// StartRingbufReader starts a goroutine reading drop events from the
	// eBPF ring buffer. lookupRecorder resolves a per-container recorder
	// from the cgroup ID embedded in each drop event. Each event carries
	// its full {pid, comm, binary_path} attribution from sk_storage
	// (populated at LSM socket_connect) — no secondary lookup is needed.
	// auditMode is a live cell — the reader Loads it on every event so
	// applyJoinerPolicy mode flips reach actionForDrop without restarting
	// the reader. Returns a stop function.
	StartRingbufReader(
		ctx context.Context,
		lookupRecorder func(cgroupID uint64) *ViolationRecorder,
		auditMode *atomic.Bool,
	) (stop func(), err error)

	// AttachCgroup attaches the eBPF program to a container's cgroup.
	// Returns a CgroupLink that must be closed to detach.
	AttachCgroup(cgroupPath string) (CgroupLink, error)

	// AddSockKnownCgroup registers a container cgroup id with the sock_attr
	// LSM filter so sockets created by tasks in that cgroup populate
	// sk_storage. Call at the same time as AttachCgroup. No-op when LSM
	// attach failed at load time (degraded mode).
	AddSockKnownCgroup(cgroupID uint64) error

	// RemoveSockKnownCgroup unregisters a container cgroup id. Safe to call
	// after Detach — existing sk_storage entries remain valid until the
	// kernel destroys each socket.
	RemoveSockKnownCgroup(cgroupID uint64)

	// SetMode updates the eBPF config map to switch between audit (true)
	// and block (false) mode at runtime. Used when a build container
	// joins a netns that was prepared by a sibling in a different mode.
	SetMode(audit bool) error

	// Close closes eBPF maps and programs. Does NOT close cgroup links —
	// those are closed individually via CgroupLink.Close().
	Close() error
}

// CgroupLink represents an eBPF program attached to a single cgroup.
type CgroupLink interface {
	Close() error
}
