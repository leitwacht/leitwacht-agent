package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// agentMark is the fwmark set on the proxy's upstream DNS sockets
// (via SO_MARK) so nftables can skip redirect for those packets.
const agentMark = 0x5E17

// containerScopeCgroup adjusts a process-cgroup path so the BPF
// program attaches at the container's outer scope rather than at an
// inner /init sub-cgroup.
//
// Docker with the systemd cgroup driver on cgroup v2 places the
// container's main PID in .../docker-<id>.scope/init/. Any sub-cgroup
// the container creates internally (e.g., buildkitd's per-RUN runc
// cgroup at .scope/buildkit/<id>/) is a SIBLING of /init, not a
// descendant. BPF cgroup_skb programs attached to /init therefore
// never see those sub-cgroups' egress.
//
// Walking up to the scope itself lets cgroup-v2's hierarchical BPF
// inheritance reach every sub-cgroup the container creates. For
// container runtimes that don't use a /init sub-cgroup (containerd
// on cgroup v2, kubepods, rootless modes) the path is unchanged.
func containerScopeCgroup(cgroupPath string) string {
	const initSuffix = "/init"

	if strings.HasSuffix(cgroupPath, initSuffix) && len(cgroupPath) > len(initSuffix) {
		return cgroupPath[:len(cgroupPath)-len(initSuffix)]
	}

	return cgroupPath
}

// ScopeCgroup is containerScopeCgroup for callers outside the package
// (the handler's pre-attach freeze targets the same scope the egress
// program attaches at, so every sub-cgroup the container creates is
// covered).
func ScopeCgroup(cgroupPath string) string { return containerScopeCgroup(cgroupPath) }

var (
	// ErrNetnsInodeZero is returned when the netns inode resolves to zero.
	ErrNetnsInodeZero = errors.New("netns inode is zero")
	// ErrMaxConcurrent is returned when the max concurrent enforcement limit is reached.
	ErrMaxConcurrent = errors.New("max concurrent enforcement reached")
	// ErrAttachInProgress is returned when a second Attach for the same
	// container arrives while the first is still running. The first call
	// owns the outcome; callers must not treat this as an attach failure.
	ErrAttachInProgress = errors.New("attach already in progress for container")
)

// ReportFunc is the callback type for periodic bucket flush reports.
// The enforcer package calls this to deliver stats without depending on reporter.
type ReportFunc func(ctx context.Context, info ContainerInfo, stats *EgressStats, interim bool, bucketTS time.Time)

// NetnsContext owns all netns-scoped state (DNS proxy, nftables, eBPF objects),
// shared across sibling containers in the same Kubernetes pod.
type NetnsContext struct {
	mu sync.RWMutex // protects cgroupRecorders, pids, and projectInfo

	inode      uint64
	primaryPID int
	// auditMode must be atomic because the ringbuf reader Loads it on
	// every drop event while applyJoinerPolicy Stores from the watcher
	// goroutine when a sibling joins with a different policy.
	auditMode atomic.Bool

	// egressAttached gates the DNS attach-liveness signal (the reserved
	// `attached` reply) on the cgroup_skb/egress program actually being
	// linked, not merely the DNS proxy being up. Set true once egress is
	// live: in attachPodLink (K8s pod cgroup, before any container runs),
	// at the end of Attach, and for a prepared sibling. On K8s the pod-level
	// attach carries the audit-all placeholder, so until the build
	// container's Attach reconciles the netns, egress is allowed and logged
	// (a known, short window). Without this,
	// the DNS proxy answers `attached` as soon as it starts in initNetnsContext — which on the non-pod path precedes
	// AttachCgroup — so a gated entrypoint (probe-detonate's waitForAgent /
	// leitwacht-init) could proceed in the window before egress enforcement
	// is live and miss the first packets. Atomic: Stored from attach paths,
	// Loaded by the DNS proxy goroutine on every reserved-name query.
	egressAttached atomic.Bool

	ebpf           EBPFHandle
	dnsProxy       *DNSProxy
	stopRingbuf    func()
	dockerUpstream *net.UDPConn // pre-bound marked socket for Docker DNS; nil on K8s

	refcount        int                           // protected by Manager.mu
	cgroupRecorders map[uint64]*ViolationRecorder // cgroup_id -> per-container recorder
	pids            map[string]int                // containerID -> pid, for primaryPID update

	// joinerDeny / joinerAllow track which deny- and static-allow-map
	// entries each joiner contributed so Detach can reverse them.
	// Without this, two siblings of the same netns with disjoint IP
	// rules union over the netns lifetime — an "allow" job inheriting
	// deny IPs from a previous "block" sibling once per-job rule sets
	// land, or worse, a job inheriting another job's IP allowances.
	// The sinkhole IP is owned by the netns init, not a joiner, and
	// lives outside these maps.
	// Protected by Manager.mu (same as refcount).
	joinerDeny  map[string][]ipRuleKey // containerID -> entries
	joinerAllow map[string][]ipRuleKey // containerID -> entries

	// members lists the attached containers' policies in attach order;
	// the effective DNS proxy policy and eBPF mode are the strictest of
	// them (reconcileNetnsPolicy). Protected by Manager.mu.
	members []netnsMember

	// effective is the policy the DNS proxy and eBPF mode currently
	// follow. Protected by Manager.mu.
	effective *policy.ResolvedPolicy

	// denyOwners / allowOwners refcount each map key across the
	// containers sharing the netns (key -> owner -> priority). Two
	// containers with an identical rule own the same key; the map value
	// is the minimum priority across owners and the key is deleted only
	// when the last owner leaves. Protected by Manager.mu.
	denyOwners  ipOwners
	allowOwners ipOwners

	// projectInfo stores CI metadata from the first container that provides it
	// (e.g., init-permissions). Siblings without CI_PROJECT_PATH inherit this
	// so their reports include proper job attribution.
	projectInfo ContainerInfo

	// sharedDNSRecorder collects DNS activity from all containers in the pod.
	// Used so that sibling DNS queries (e.g., helper doing git clone) are
	// visible in the build container's report. eBPF packet violations still
	// go to per-cgroup recorders for correct attribution.
	sharedDNSRecorder *ViolationRecorder

	// dnsCache is a job-lifetime IP → domain map populated by DNS proxy
	// observations and consulted by all recorders (shared DNS + per-cgroup
	// packet) at flush time to attribute bare-IP violations before ship.
	// Closes the concurrency race where server-side reconciliation could
	// miss a bare violation whose DNS report raced with its packet report.
	dnsCache *DNSCache

	// Pod-cgroup attach state. When podAttached is true, the eBPF program
	// is attached at the pod cgroup (the parent of every container in the
	// pod) — set up by AttachPodSandbox when the K8s pause container fires
	// /tasks/start, before any user container's task is running. The kernel
	// evaluates cgroup_skb programs across the whole hierarchy, so every
	// container in the pod is filtered automatically and attachEnforcer
	// skips the per-container AttachCgroup call. Per-container attribution
	// is preserved because bpf_get_current_cgroup_id() returns the task's
	// leaf cgroup, not the attached cgroup.
	podAttached   bool
	podCgroupLink CgroupLink
	podCgroupID   uint64
	podUID        string
	sandboxID     string

	ready    chan struct{}
	initErr  error
	tornDown bool // protected by Manager.mu — prevents double teardown from deferred goroutines

	// DNS bucket flush goroutine coordination.
	dnsFlushStarted atomic.Bool
	dnsFlushCancel  context.CancelFunc
	dnsFlushDone    chan struct{}
	// Updated by Attach when a new primary container joins — DNS goroutine
	// reads this atomically to attribute reports to the current container.
	dnsContainerInfo atomic.Pointer[ContainerInfo]
}

// lookupDNSRecorder returns the shared DNS recorder for DNS proxy queries.
// All DNS activity across sibling containers lands in one recorder, ensuring
// the build container's report includes helper DNS lookups (e.g., git clone).
func (nctx *NetnsContext) lookupDNSRecorder(_ uint64) *ViolationRecorder {
	return nctx.sharedDNSRecorder
}

// lookupPacketRecorder returns the per-cgroup ViolationRecorder for eBPF
// ringbuf drop events. Falls back to the first registered recorder if the
// cgroup ID is unknown.
func (nctx *NetnsContext) lookupPacketRecorder(cgroupID uint64) *ViolationRecorder {
	nctx.mu.RLock()
	defer nctx.mu.RUnlock()

	if rec := nctx.cgroupRecorders[cgroupID]; rec != nil {
		return rec
	}

	// Fallback: cgroupID unknown, return any registered recorder. Map
	// iteration order is randomised, so callers must not depend on
	// which sibling's recorder is picked — they just need to record
	// the event under *something* attributable to the netns.
	for _, rec := range nctx.cgroupRecorders {
		return rec
	}

	return nil
}

// Enforcer manages enforcement for a single container.
type Enforcer struct {
	info   ContainerInfo
	policy *policy.ResolvedPolicy
	cgroup string
	pid    int
	logger *slog.Logger

	ctx        *NetnsContext // back-ref to shared netns context
	cgroupLink CgroupLink    // this container's cgroup attachment
	cgroupID   uint64        // for attribution + cgroupRecorders key
	recorder   *ViolationRecorder

	// cgroupPaths is every cgroup path the container's events can be
	// attributed to: the BPF attach point (scope) first, then the original
	// /init leaf when scope-stripping applied.
	cgroupPaths []string

	// sockAttrCgroupIDs are the cgroup_ids registered with the LSM
	// sock_attr filter. Includes the BPF attach point's inode plus
	// any stripped /init leaf (Docker systemd-driver containers
	// report leaf cgroup_id via bpf_get_current_cgroup_id() rather
	// than the attach point's inode, so both must be admitted).
	sockAttrCgroupIDs []uint64

	// dnsPIDCgroupIDs are the cgroup_ids registered with the DNS
	// PID tracker. Same shape and same reason as sockAttrCgroupIDs.
	dnsPIDCgroupIDs []uint64

	// Per-container packet bucket flush goroutine.
	packetFlushCancel context.CancelFunc
	packetFlushDone   chan struct{}
}

// Manager tracks all active enforcers across containers.
type Manager struct {
	mu sync.Mutex
	// containerID → Enforcer (nil sentinel during in-flight Attach).
	enforcers map[string]*Enforcer
	// passive marks containerIDs in enforcers that were admitted as passive
	// sentinels; they are excluded from the maxConc count.
	passive map[string]struct{}
	// netns inode → NetnsContext (refcounted, shared across pod siblings).
	netnsContexts map[uint64]*NetnsContext
	logger        *slog.Logger
	maxConc       int
	upstreams     []string // DNS upstream servers
	trustedCIDRs  []net.IPNet
	platform      Platform

	// NetnsGrace is how long a NetnsContext stays alive after its last container
	// detaches. Allows sibling containers (e.g., build after init-permissions)
	// to join the existing context. Zero means no grace period (immediate teardown).
	NetnsGrace time.Duration

	// IsDocker indicates the agent is running with a Docker runtime.
	// When true, the proxy chains upstream DNS through Docker's embedded
	// DNS (127.0.0.11) via a marked socket to preserve service discovery.
	IsDocker bool

	// AgentVersion is plumbed through to every per-netns DNS proxy and
	// echoed in the TXT answer for the attachment-liveness name.
	AgentVersion string

	// BucketInterval is the periodic flush interval. Zero disables bucketing.
	BucketInterval time.Duration
	// ReportFunc is the callback for delivering bucket flush reports.
	// Wired by the handler to Reporter.Report. Nil if bucketing is disabled.
	ReportFunc ReportFunc

	// DNS PID tracker (global kprobe, per-container cgroup registration).
	dnsPIDTracker *DNSPIDTracker

	// Credwatch LSM (global, not per-container).
	// Fields used by credwatch_linux.go; appear unused on non-linux builds.
	credwatchCfg               CredwatchConfig                              //nolint:unused,nolintlint // used in credwatch_linux.go
	credwatchLSMLoaded         bool                                         //nolint:unused,nolintlint // true after successful LSM load
	credwatchState             any                                          //nolint:unused,nolintlint // *credwatchLSMImpl on Linux
	credwatchStop              func()                                       //nolint:unused,nolintlint // stops ring buffer reader
	credwatchContainers        map[string]*credwatchContainerState          //nolint:unused,nolintlint // containerID → tracked state
	credwatchCgroupToContainer map[uint64]string                            //nolint:unused,nolintlint // cgroupID → containerID
	OnCredwatchEvent           func(event CredwatchEvent)                   //nolint:unused,nolintlint // callback for kill + report
	onDNSViolation             func(cgroupID uint64, domain, action string) // called from DNS proxy on block-mode violations

	// Proc_mem LSM (global, not per-container).
	// Fields used by proc_mem_linux.go; appear unused on non-linux builds.
	procMemCfg        ProcMemConfig                     //nolint:unused,nolintlint // used in proc_mem_linux.go
	procMemState      any                               //nolint:unused,nolintlint // *procMemLSMImpl on Linux
	procMemStop       func()                            //nolint:unused,nolintlint // stops ring buffer reader
	procMemLSMLoaded  bool                              //nolint:unused,nolintlint // true after successful LSM load
	procMemContainers map[string]*procMemContainerState //nolint:unused,nolintlint // containerID → tracked state
	procMemCgroupMap  map[uint64]string                 //nolint:unused,nolintlint // cgroupID → containerID
	OnProcMemEvent    func(event ProcMemEvent)          //nolint:unused,nolintlint // callback for kill + report

	// inFlightReports tracks bucket-flush ReportFunc invocations that
	// have started but not returned. DetachAll waits on this WaitGroup
	// (bounded by BucketInterval) so the daemon doesn't exit with
	// goroutines mid-POST and lose final reports to SIGKILL.
	inFlightReports sync.WaitGroup

	// shutdownCh is closed by DetachAll so background goroutines
	// (currently deferredTeardown) can break out of their grace-period
	// waits instead of blocking the process past SIGTERM.
	shutdownCh     chan struct{}
	shutdownChOnce sync.Once

	// EnvNamesFn, when non-nil, is the live env-name reader (typically
	// procenv.Names). The recorder calls it at RECORD time — when the
	// offending PID is still alive — and caches the result for the
	// bucket window so the same PID making many events is one /proc
	// read. CE wires this; EE leaves it nil.
	EnvNamesFn func(pid int) []string
}

// Platform returns the Platform implementation this manager was
// constructed with. Used by the BuildKit egress attach to load its own
// EBPFHandle without piping the platform through main() separately.
func (m *Manager) Platform() Platform {
	return m.platform
}

// SetOnDNSViolation sets the callback invoked when a DNS violation occurs
// in block mode. CE wires this to kill the container; EE may quarantine.
func (m *Manager) SetOnDNSViolation(fn func(cgroupID uint64, domain, action string)) {
	m.onDNSViolation = fn
}

// CgroupPathForPID returns the cgroup v2 path of a process via the
// platform (the kernel's view, not the runtime's spec).
func (m *Manager) CgroupPathForPID(pid int) (string, error) {
	return m.platform.GetCgroupPath(pid)
}

// ContainerIDForCgroup resolves a cgroup ID to a container ID by searching
// the credwatch and proc_mem cgroup-to-container maps.
func (m *Manager) ContainerIDForCgroup(cgroupID uint64) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if id, ok := m.credwatchCgroupToContainer[cgroupID]; ok {
		return id
	}

	if id, ok := m.procMemCgroupMap[cgroupID]; ok {
		return id
	}

	return ""
}

// ContainerInfo returns the CI attribution recorded for an attached
// container, without tearing anything down. Returns ok=false when the
// container has no live Enforcer (never attached, already detached, or
// still mid-Attach).
//
// Exists for the LSM observe-only path: an observed detection must be
// reported with full project/job attribution, but must NOT detach the
// container the way an enforced hit does. Detach was previously the only
// way to obtain a ContainerInfo, which made "report it" and "leave the
// workload running" mutually exclusive.
func (m *Manager) ContainerInfo(containerID string) (ContainerInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.enforcers[containerID]
	if !ok || e == nil {
		return ContainerInfo{}, false
	}

	return e.info, true
}

// AttachedContainerIDs returns the IDs of all fully-attached containers (those
// with a live Enforcer). The reconcile loop diffs this against the runtime's
// running set to find containers whose exit event was missed. Reserved-but-not-
// yet-attached slots (nil value, set during the Attach critical section) are
// excluded — they are mid-Attach, not stale, and must not be reconciled away.
func (m *Manager) AttachedContainerIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]string, 0, len(m.enforcers))
	for id, e := range m.enforcers {
		if e != nil {
			ids = append(ids, id)
		}
	}

	return ids
}

// NewManager creates an enforcement manager with the given configuration.
func NewManager(
	logger *slog.Logger, maxConcurrent int, upstreams []string,
	trustedCIDRs []net.IPNet, platform Platform, credwatchCfg CredwatchConfig, procMemCfg ProcMemConfig,
) *Manager {
	return &Manager{
		enforcers:                  make(map[string]*Enforcer),
		passive:                    make(map[string]struct{}),
		netnsContexts:              make(map[uint64]*NetnsContext),
		logger:                     logger,
		maxConc:                    maxConcurrent,
		upstreams:                  upstreams,
		trustedCIDRs:               trustedCIDRs,
		platform:                   platform,
		credwatchCfg:               credwatchCfg,
		procMemCfg:                 procMemCfg,
		credwatchContainers:        make(map[string]*credwatchContainerState),
		credwatchCgroupToContainer: make(map[uint64]string),
		procMemContainers:          make(map[string]*procMemContainerState),
		procMemCgroupMap:           make(map[uint64]string),
		shutdownCh:                 make(chan struct{}),
	}
}

// Attach sets up enforcement for a container. Sibling containers in the same
// pod (same netns) share a single NetnsContext (DNS proxy, nftables, eBPF
// objects) but each get their own cgroup attachment and ViolationRecorder.
func (m *Manager) Attach(_ context.Context, info ContainerInfo, pid int, pol *policy.ResolvedPolicy) (*Enforcer, error) {
	if pol.Action == "allow" {
		m.logger.Info("skipping enforcement (allow mode)", "container_id", truncID(info.ContainerID))

		// Nothing to enforce for this job: make sure the gate is open.
		if ino, err := m.platform.NetnsInode(pid); err == nil && ino != 0 {
			m.mu.Lock()
			nctx := m.netnsContexts[ino]
			m.mu.Unlock()

			if nctx != nil {
				nctx.egressAttached.Store(true)
			}
		}

		return nil, nil //nolint:nilnil // nil,nil signals "skip, no error"
	}

	netnsIno, netnsErr := m.platform.NetnsInode(pid)
	if netnsErr != nil {
		m.logger.Warn("netns inode lookup failed; using standalone context",
			"container_id", truncID(info.ContainerID),
			"pid", pid,
			"error", netnsErr,
		)

		netnsIno = 0
	}

	m.mu.Lock()

	// A duplicate start event for a container that is already enforced is
	// harmless: report the existing handle. A duplicate that arrives
	// while the first Attach is still in flight has no handle yet and is
	// reported as ErrAttachInProgress. Both are checked before the
	// capacity limit so a re-delivered event never reads as "full".
	if existing, exists := m.enforcers[info.ContainerID]; exists {
		m.mu.Unlock()
		m.logger.Warn("container already enforced, ignoring duplicate attach",
			"container_id", truncID(info.ContainerID),
		)

		if existing == nil {
			return nil, ErrAttachInProgress
		}

		return existing, nil
	}

	// Passive sentinel attaches (non-enrolled projects: audit, no rules)
	// enforce nothing, so they neither count against the limit nor can be
	// refused by it. Counting only enforcing attaches is the simplest
	// correct bound: the limit exists to cap enforcement state, and
	// refusing a sentinel would break the init-container gate for jobs that
	// opted out of enforcement.
	passive := policyStrictness(pol) == 0

	// Fail closed at capacity: returning (nil, nil) here used to leave
	// the container running with no enforcement and no signal to the
	// caller, which only logged on error.
	if !passive && len(m.enforcers)-len(m.passive) >= m.maxConc {
		m.mu.Unlock()
		m.logger.Error("max concurrent enforcement reached, container not enforced",
			"container_id", truncID(info.ContainerID),
			"max", m.maxConc,
		)

		return nil, fmt.Errorf("%w (%d)", ErrMaxConcurrent, m.maxConc)
	}

	m.enforcers[info.ContainerID] = nil

	if passive {
		m.passive[info.ContainerID] = struct{}{}
	}
	m.mu.Unlock()

	releaseSlot := func() {
		m.mu.Lock()
		delete(m.enforcers, info.ContainerID)
		delete(m.passive, info.ContainerID)
		m.mu.Unlock()
	}

	//nolint:contextcheck // context.Background() intentional — initNetnsContext spawns goroutines that outlive caller
	nctx, created, err := m.acquireOrCreateNetnsContext(
		netnsIno,
		func(n *NetnsContext) error {
			return m.initNetnsContext(n, pid, pol)
		},
	)
	if err != nil {
		releaseSlot()

		return nil, err
	}

	// Both creator and joiner paths register their IP allow/deny rules
	// through the same per-container ownership maps so Detach can
	// reverse them. The sinkhole entry is netns-lifetime and was seeded
	// once during initNetnsContext.
	m.mu.Lock()
	ruleErr := m.addJoinerIPRules(nctx, info.ContainerID, pol)

	m.addNetnsMember(nctx, info.ContainerID, pol)

	if !created {
		// Joiner-only: reconcile the DNS proxy policy and eBPF mode
		// against every attached member. Creator already installed both
		// during initNetnsContext.
		m.reconcileNetnsPolicy(nctx)
	}
	m.mu.Unlock()

	// In block mode a deny that did not reach the datapath is a permitted
	// destination the operator asked to block: fail the attach so the
	// caller can refuse to run the container. Audit mode only observes.
	if ruleErr != nil && pol.Action == policy.ActionBlock {
		m.rollbackFailedAttach(info.ContainerID, nctx, created, netnsIno, releaseSlot)

		return nil, ruleErr
	}

	e, attachErr := m.attachEnforcer(info, pid, pol, nctx)
	if attachErr != nil {
		m.rollbackFailedAttach(info.ContainerID, nctx, created, netnsIno, releaseSlot)

		return nil, attachErr
	}

	// Egress is live and the netns has been reconciled to the effective
	// policy including this container's. Arm the DNS attach-liveness signal
	// (already armed on K8s by the pod-level attach; this is what arms it
	// on the Docker/non-pod path).
	nctx.egressAttached.Store(true)

	m.finalizeAttach(info, e, nctx) //nolint:contextcheck // bucket reporters use context.Background() intentionally — outlive caller

	return e, nil
}

// rollbackFailedAttach undoes a partially completed Attach: frees the
// concurrency slot and reverses the IP rules installed for this
// container. Detach can't do the latter — releaseSlot has already dropped
// the container from m.enforcers, so Detach returns early and never
// reaches removeJoinerIPRules. Without this the entries outlive a
// container that was never enforced, and on the joiner path (the netns
// survives) a sibling would inherit its allow rules.
//
// The creator owns the netns context: a failure means no other container
// is using it yet, so tear it down rather than leaving an orphan.
// Joiners share the context with at least one already-attached sibling,
// so it is left alone.
func (m *Manager) rollbackFailedAttach(
	containerID string, nctx *NetnsContext, created bool, netnsIno uint64, releaseSlot func(),
) {
	releaseSlot()

	m.mu.Lock()
	m.removeJoinerIPRules(nctx, containerID)

	if m.removeNetnsMember(nctx, containerID) && !created {
		m.reconcileNetnsPolicy(nctx)
	}

	if created && netnsIno != 0 {
		delete(m.netnsContexts, netnsIno)
	}
	m.mu.Unlock()

	if created {
		m.teardownNetnsContext(nctx)
	}
}

// netnsMember is one attached container's policy, in attach order.
type netnsMember struct {
	id  string
	pol *policy.ResolvedPolicy
}

// policyStrictness ranks a member policy: 2 enforcing (block), 1 audit
// with at least one rule, 0 passive (audit, no rules — helper and
// non-enrolled sentinels).
func policyStrictness(pol *policy.ResolvedPolicy) int {
	switch {
	case pol.Action != policy.ActionAudit:
		return 2
	case len(pol.RulesForJob("")) > 0 || len(pol.DenyIPs) > 0:
		return 1
	default:
		return 0
	}
}

// addNetnsMember records a container's policy on the shared context.
// Caller must hold Manager.mu.
func (m *Manager) addNetnsMember(nctx *NetnsContext, containerID string, pol *policy.ResolvedPolicy) {
	m.removeNetnsMember(nctx, containerID)
	nctx.members = append(nctx.members, netnsMember{id: containerID, pol: pol})
}

// removeNetnsMember drops a container's policy from the shared context
// and reports whether it was present. Caller must hold Manager.mu.
func (m *Manager) removeNetnsMember(nctx *NetnsContext, containerID string) bool {
	for i, mem := range nctx.members {
		if mem.id == containerID {
			nctx.members = append(nctx.members[:i], nctx.members[i+1:]...)

			return true
		}
	}

	return false
}

// reconcileNetnsPolicy points the shared DNS proxy and eBPF mode at the
// strictest member policy. The datapath and proxy hold one mode per
// netns, so the effective policy must never be weaker than any member
// still attached: a passive or audit joiner can no longer flip an
// enforcing pod to audit, and when the enforcing member leaves the
// remaining members' policy takes over. Among equally strict members the
// most recent joiner wins, which preserves the "real policy replaces the
// helper's audit-all placeholder" behaviour. No-op with no members (the
// context is on its way out). Caller must hold Manager.mu.
func (m *Manager) reconcileNetnsPolicy(nctx *NetnsContext) {
	bestRank := -1

	for _, mem := range nctx.members {
		if r := policyStrictness(mem.pol); r > bestRank {
			bestRank = r
		}
	}

	if bestRank < 0 {
		return
	}

	// Among equally strict members keep the policy already in force if it is
	// still a member (by identity or fingerprint); otherwise the most recent
	// joiner wins.
	var best *policy.ResolvedPolicy

	for _, mem := range nctx.members {
		if policyStrictness(mem.pol) != bestRank {
			continue
		}

		if nctx.effective != nil && (mem.pol == nctx.effective || policyFingerprint(mem.pol) == policyFingerprint(nctx.effective)) {
			best = nctx.effective

			break
		}

		best = mem.pol
	}

	// DNS-derived allow entries carry the priority of the rule that
	// authorised them under the policy in force at resolution time. When
	// the effective policy actually changes (different fingerprint) they
	// are stale and could outrank the new policy's denies; drop them and
	// let live queries re-seed. A sibling joining or leaving with an
	// identical policy does not count as a change.
	if nctx.effective != nil && nctx.ebpf != nil && policyFingerprint(nctx.effective) != policyFingerprint(best) {
		if err := nctx.ebpf.FlushAllowedIPs(); err != nil {
			m.logger.Warn("flush dns allow map on policy change", "netns_inode", nctx.inode, "error", err)
		}
	}

	nctx.effective = best

	if nctx.dnsProxy != nil {
		nctx.dnsProxy.UpdatePolicy(best)
	}

	wantAudit := best.Action == policy.ActionAudit
	if wantAudit == nctx.auditMode.Load() {
		return
	}

	modeErr := nctx.ebpf.SetMode(wantAudit)
	if modeErr != nil {
		m.logger.Error("update ebpf mode on netns membership change", "error", modeErr)

		return
	}

	// Store only after SetMode succeeds: the kernel and the ringbuf
	// reader's view must not disagree on what mode is in effect.
	nctx.auditMode.Store(wantAudit)
	m.logger.Info("ebpf mode updated on netns membership change",
		"netns_inode", nctx.inode,
		"audit", wantAudit,
		"members", len(nctx.members),
	)
}

// policyFingerprint identifies a policy by content: project, action,
// version and the rule list that drives the datapath. Two members running
// the same job's policy have equal fingerprints even as distinct values.
func policyFingerprint(pol *policy.ResolvedPolicy) string {
	h := sha256.New()

	fmt.Fprintf(h, "%s|%s|%d\n", pol.ProjectPath, pol.Action, pol.Version)

	for _, r := range pol.RulesForJob("") {
		fmt.Fprintf(h, "r|%s|%s|%s|%v\n", r.Pattern, r.PatternType, r.Action, r.Ports)
	}

	for _, d := range pol.DenyIPs {
		fmt.Fprintf(h, "d|%s|%d\n", d.IP, d.Port)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// PrepareNetns sets up the netns-level DNS infrastructure (proxy, nftables,
// eBPF) for a sibling container that lacks job metadata (e.g., K8s helper
// container). DNS queries are recorded in audit-all mode. When the build
// container starts later and calls Attach, it joins this existing NetnsContext
// and swaps in the real policy.
func (m *Manager) PrepareNetns(containerID string, pid int, cgroupPath string) error {
	netnsIno, netnsErr := m.platform.NetnsInode(pid)
	if netnsErr != nil {
		return fmt.Errorf("netns inode lookup: %w", netnsErr)
	}

	if netnsIno == 0 {
		return fmt.Errorf("pid %d: %w", pid, ErrNetnsInodeZero)
	}

	m.mu.Lock()

	if _, exists := m.enforcers[containerID]; exists {
		m.mu.Unlock()

		return nil
	}

	if len(m.enforcers) >= m.maxConc {
		m.mu.Unlock()

		return fmt.Errorf("%w (%d)", ErrMaxConcurrent, m.maxConc)
	}

	m.enforcers[containerID] = nil
	m.mu.Unlock()

	releaseSlot := func() {
		m.mu.Lock()
		delete(m.enforcers, containerID)
		m.mu.Unlock()
	}

	auditPol := &policy.ResolvedPolicy{
		Action:   policy.ActionAudit,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": nil},
	}

	nctx, created, err := m.acquireOrCreateNetnsContext(netnsIno, func(n *NetnsContext) error {
		return m.initNetnsContext(n, pid, auditPol)
	})
	if err != nil {
		releaseSlot()

		return fmt.Errorf("init netns context: %w", err)
	}

	m.mu.Lock()
	m.addNetnsMember(nctx, containerID, auditPol)
	m.mu.Unlock()

	e, attachErr := m.attachEnforcer(
		ContainerInfo{ContainerID: containerID, CgroupPath: cgroupPath},
		pid, auditPol, nctx,
	)
	if attachErr != nil {
		releaseSlot()

		m.mu.Lock()
		m.removeNetnsMember(nctx, containerID)
		m.mu.Unlock()

		if created {
			m.mu.Lock()
			delete(m.netnsContexts, netnsIno)
			m.mu.Unlock()

			m.teardownNetnsContext(nctx)
		}

		return fmt.Errorf("attach sibling cgroup: %w", attachErr)
	}

	m.mu.Lock()
	m.enforcers[containerID] = e
	m.mu.Unlock()

	// The sibling's attach (or the pod link on a pod-attached netns) is
	// live: arm the DNS attach-liveness signal. leitwacht-initc is such a
	// sibling and must be released here.
	nctx.egressAttached.Store(true)

	if created {
		m.logger.Info("netns prepared for sibling",
			"container_id", truncID(containerID),
			"netns_inode", netnsIno,
		)
	} else {
		m.logger.Info("sibling joined existing netns",
			"container_id", truncID(containerID), "netns_inode", netnsIno)
	}

	return nil
}

// acquireOrCreateNetnsContext atomically returns the NetnsContext for
// netnsIno. If a context already exists, this caller is a joiner: the
// returned nctx is ready (initFn is NOT called) and any creator-side
// initErr is propagated. If no context exists, this caller is the
// creator: initFn runs synchronously, the ready channel is closed on
// the way out, and m.netnsContexts is cleaned up on init failure.
//
// netnsIno == 0 is the standalone case (netns inode lookup failed):
// every call creates its own throwaway nctx that's never visible to
// other callers, so the caller is always the creator.
//
// Pure over (m, netnsIno, initFn): no caller-side ready/initErr
// handling, no caller-side m.netnsContexts mutation. Callers own
// post-acquire work (attachEnforcer / attachPodLink / policy swap)
// because that's what genuinely differs per entry point. The four
// entry points (Attach, PrepareNetns, AttachPodSandbox creator path,
// AttachPodSandbox promote-existing path) used to duplicate this
// dance with subtly different rollback chains; consolidating it here
// removes the nestif/funlen/gocognit/cyclop nolints those carried.
func (m *Manager) acquireOrCreateNetnsContext(
	netnsIno uint64,
	initFn func(*NetnsContext) error,
) (*NetnsContext, bool, error) {
	m.mu.Lock()

	if netnsIno != 0 {
		if existing := m.netnsContexts[netnsIno]; existing != nil {
			m.mu.Unlock()

			<-existing.ready

			if existing.initErr != nil {
				return nil, false, existing.initErr
			}

			return existing, false, nil
		}
	}

	nctx := &NetnsContext{
		inode:           netnsIno,
		cgroupRecorders: make(map[uint64]*ViolationRecorder),
		pids:            make(map[string]int),
		ready:           make(chan struct{}),
	}

	if netnsIno != 0 {
		m.netnsContexts[netnsIno] = nctx
	}

	m.mu.Unlock()

	initErr := initFn(nctx)
	if initErr != nil {
		nctx.initErr = initErr

		close(nctx.ready)

		if netnsIno != 0 {
			m.mu.Lock()
			delete(m.netnsContexts, netnsIno)
			m.mu.Unlock()
		}

		return nil, true, initErr
	}

	close(nctx.ready)

	return nctx, true, nil
}

// finalizeAttach completes a successful Attach: stores the enforcer in
// m.enforcers, records project info for sibling inheritance, attaches
// buildkit (if configured), starts bucket reporters, and registers
// credwatch/proc_mem entries. Common to both creator and joiner paths in Attach.
func (m *Manager) finalizeAttach(info ContainerInfo, e *Enforcer, nctx *NetnsContext) {
	m.mu.Lock()
	m.enforcers[info.ContainerID] = e
	m.mu.Unlock()

	// Store project metadata so siblings without CI_PROJECT_PATH
	// (init-permissions, helper containers) can inherit job attribution.
	if info.ProjectPath != "" {
		nctx.mu.Lock()
		if nctx.projectInfo.ProjectPath == "" {
			nctx.projectInfo = info
		}
		nctx.mu.Unlock()
	}

	m.startPacketBucketReporter(e)
	m.startDNSBucketReporter(info, nctx)

	// "off" mode skips the attach entirely (container not monitored);
	// "observe" attaches with the BPF observe-only bit; "enforce" (and the
	// empty/unset default) attaches in killing mode.
	if info.CredwatchMode != policy.LSMModeOff {
		m.AttachCredwatchPaths(info.ContainerID, e.lsmCgroupPaths(), info.AllowCredWatch, info.CredwatchMode == policy.LSMModeObserve)
	}

	if info.ProcMemMode != policy.LSMModeOff {
		m.AttachProcMemPaths(info.ContainerID, e.lsmCgroupPaths(), info.AllowProcMemRead, info.ProcMemMode == policy.LSMModeObserve)
	}
}

// parseRuleIP resolves a cidr-rule pattern to the single host address
// the datapath maps are keyed on.
//
// Patterns reach us in three shapes: a bare address, and the /32 and
// /128 single-host forms the server writes (IgnoreAnomaly appends /32,
// and the CE loader normalises `ip:` entries the same way). net.ParseIP
// rejects all of the prefixed forms, which is why those rules used to
// be dropped here without a word — an operator would ignore an IP
// anomaly, see the rule appear in the UI, and never find out it had no
// effect on the wire.
//
// Genuine multi-host prefixes are not supported yet: the deny and allow
// maps are exact-match hashes, so a /24 would need expansion or an LPM
// trie. Reject them loudly rather than half-applying them.
func parseRuleIP(pattern string, log *slog.Logger) (net.IP, bool) {
	if !strings.Contains(pattern, "/") {
		ip := net.ParseIP(pattern)
		if ip == nil {
			log.Warn("skip ip rule: unparseable address", "pattern", pattern)

			return nil, false
		}

		return ip, true
	}

	ip, network, err := net.ParseCIDR(pattern)
	if err != nil {
		log.Warn("skip ip rule: unparseable cidr", "pattern", pattern, "error", err)

		return nil, false
	}

	ones, bits := network.Mask.Size()
	if ones != bits {
		log.Warn("skip ip rule: multi-host prefixes are not supported",
			"pattern", pattern, "prefix_len", ones)

		return nil, false
	}

	return ip, true
}

// ipv4Only rejects addresses the datapath cannot key on. PackAllowKey
// returns an all-zero key for anything without a 4-byte form, so an
// IPv6 rule would install a bogus 0.0.0.0 entry rather than the address
// asked for — and the egress program drops all IPv6 unconditionally
// anyway. Refusing loudly beats installing a rule that reads as
// enforced and isn't.
func ipv4Only(ip net.IP, pattern string, log *slog.Logger) bool {
	if ip.To4() != nil {
		return true
	}

	log.Warn("skip ip rule: IPv6 is not supported by the egress maps", "pattern", pattern)

	return false
}

// ipRuleKey identifies one entry in the eBPF deny or static-allow map.
type ipRuleKey struct {
	IP   string
	Port int
}

// ipRuleEntry is a resolved IP rule ready to install: a map key plus
// the priority that decides it against a competing rule in egress.c.
type ipRuleEntry struct {
	Key  ipRuleKey
	Prio uint32
}

// collectIPRules resolves a job's cidr rules into the deny and allow
// entries to install, in composed-list order.
//
// Ordering is the whole point of the priority stamp: the datapath used
// to hardcode "deny beats allow", which diverged from the first-match-
// wins semantics the DNS proxy applies to fqdn rules. Carrying the list
// index through means one consistent rule model for names and addresses
// alike.
//
// pol.DenyIPs (the standalone blocklist — CE's `deny_ips:` stanza) fills
// in only where no rule already covers the key, at SystemRulePriority.
// On EE every entry in that field is generated from a cidr deny rule and
// is therefore already covered; in CE it is a separate concept with no
// position in any list, and must outrank everything.
func collectIPRules(pol *policy.ResolvedPolicy, log *slog.Logger) (deny, allow []ipRuleEntry) {
	// Each map holds one value per key, so a duplicate rule covering a
	// key already claimed by an earlier one must be dropped rather than
	// installed — writing it would replace a better (lower) priority
	// with a worse one and quietly invert the ruleset. Walking the list
	// in order means the first claim is the winning one.
	seenDeny := make(map[ipRuleKey]bool)
	seenAllow := make(map[ipRuleKey]bool)

	for i, r := range pol.RulesForJob("") {
		if r.PatternType != policy.PatternCIDR {
			continue
		}

		ip, ok := parseRuleIP(r.Pattern, log)
		if !ok || !ipv4Only(ip, r.Pattern, log) {
			continue
		}

		prio := policy.RulePriority(i)

		// A cidr rule with no ports means "any port on this IP",
		// which the datapath encodes as the port=0 wildcard.
		ports := r.Ports
		if len(ports) == 0 {
			ports = []int{0}
		}

		for _, port := range ports {
			entry := ipRuleEntry{Key: ipRuleKey{IP: ip.String(), Port: port}, Prio: prio}

			seen := seenAllow
			target := &allow

			if r.Action == policy.ActionDeny {
				seen = seenDeny
				target = &deny
			}

			if seen[entry.Key] {
				continue
			}

			seen[entry.Key] = true
			*target = append(*target, entry)
		}
	}

	for _, dip := range pol.DenyIPs {
		ip, ok := parseRuleIP(dip.IP, log)
		if !ok || !ipv4Only(ip, dip.IP, log) {
			continue
		}

		key := ipRuleKey{IP: ip.String(), Port: dip.Port}
		if seenDeny[key] {
			continue
		}

		deny = append(deny, ipRuleEntry{Key: key, Prio: policy.SystemRulePriority})
	}

	return deny, allow
}

// netnsOwner is the pseudo-owner id under which netns-lifetime entries
// (the DNS sinkhole) are registered in the ownership tables. No real
// container id can collide with it.
const netnsOwner = "\x00netns"

// ipOwners tracks, per map key, which owners (container ids, or
// netnsOwner) asked for the entry and at what priority. The datapath
// holds one value per key, so with several owners the value installed
// is the minimum priority across them, and the key is deleted only
// when the last owner leaves. Protected by Manager.mu.
type ipOwners map[ipRuleKey]map[string]uint32

// minPrio returns the best (lowest) priority across owners.
func minPrio(owners map[string]uint32) uint32 {
	first := true

	var best uint32

	for _, p := range owners {
		if first || p < best {
			best = p
			first = false
		}
	}

	return best
}

// ownedPut registers (owner, prio) for key and writes min(prio) across
// all owners via put. If the write fails the registration is rolled
// back so the table never claims an install that did not happen.
func (o ipOwners) ownedPut(key ipRuleKey, owner string, prio uint32, put func(prio uint32) error) error {
	owners := o[key]
	created := owners == nil

	if created {
		owners = make(map[string]uint32)
		o[key] = owners
	}

	prev, hadPrev := owners[owner]
	owners[owner] = prio

	err := put(minPrio(owners))
	if err == nil {
		return nil
	}

	switch {
	case hadPrev:
		owners[owner] = prev
	case created:
		delete(o, key)
	default:
		delete(owners, owner)
	}

	return err
}

// ownedRemove drops owner from key. The entry is deleted from the map
// only when no owner remains; otherwise the new minimum priority is
// written back so a departing owner's better priority does not linger.
func (o ipOwners) ownedRemove(key ipRuleKey, owner string, put func(prio uint32) error, del func() error) error {
	owners := o[key]
	if owners == nil {
		return nil
	}

	oldMin := minPrio(owners)

	delete(owners, owner)

	if len(owners) == 0 {
		delete(o, key)

		return del()
	}

	if newMin := minPrio(owners); newMin != oldMin {
		return put(newMin)
	}

	return nil
}

// ErrIPRuleInstall is returned by addJoinerIPRules when a deny entry
// could not be written to the datapath.
var ErrIPRuleInstall = errors.New("install ip deny rule")

// addJoinerIPRules installs a joiner's IP allow and deny entries and
// records ownership so they can be reversed at Detach. Caller must hold
// Manager.mu (same lock as nctx.refcount / joinerDeny / joinerAllow).
//
// Entries are reference-counted per key across containers sharing the
// netns: two containers contributing the same key both own it, the
// lowest priority wins, and the entry survives until the last owner
// detaches.
//
// A failed deny install is returned: a deny that is not in the map is
// a silently permitted destination. A failed allow install is only
// logged, because its failure mode is a spurious drop.
//
// The sinkhole IP is seeded once per netns by seedSinkholeDeny under
// the netnsOwner id — it is not owned by any joiner and survives
// joiner detach.
func (m *Manager) addJoinerIPRules(nctx *NetnsContext, containerID string, pol *policy.ResolvedPolicy) error {
	if nctx.joinerDeny == nil {
		nctx.joinerDeny = make(map[string][]ipRuleKey)
	}

	if nctx.joinerAllow == nil {
		nctx.joinerAllow = make(map[string][]ipRuleKey)
	}

	if nctx.denyOwners == nil {
		nctx.denyOwners = make(ipOwners)
	}

	if nctx.allowOwners == nil {
		nctx.allowOwners = make(ipOwners)
	}

	denyEntries, allowEntries := collectIPRules(pol, m.logger)

	var denyErr error

	addedDeny := nctx.joinerDeny[containerID][:0]

	for _, e := range denyEntries {
		ip := net.ParseIP(e.Key.IP)
		if ip == nil {
			continue
		}

		err := nctx.denyOwners.ownedPut(e.Key, containerID, e.Prio, func(prio uint32) error {
			return nctx.ebpf.AddDeniedIP(ip, e.Key.Port, prio)
		})
		if err != nil {
			m.logger.Warn("add joiner deny", "container", containerID, "ip", e.Key.IP, "port", e.Key.Port, "error", err)

			if denyErr == nil {
				denyErr = fmt.Errorf("%w %s:%d: %w", ErrIPRuleInstall, e.Key.IP, e.Key.Port, err)
			}

			continue
		}

		addedDeny = append(addedDeny, e.Key)
	}

	nctx.joinerDeny[containerID] = addedDeny

	addedAllow := nctx.joinerAllow[containerID][:0]

	for _, e := range allowEntries {
		ip := net.ParseIP(e.Key.IP)
		if ip == nil {
			continue
		}

		// A failed static-allow install is louder than a failed deny:
		// the map is bounded and non-evicting, so the only realistic
		// cause is exhaustion, and the symptom is a destination the
		// operator explicitly permitted getting dropped.
		err := nctx.allowOwners.ownedPut(e.Key, containerID, e.Prio, func(prio uint32) error {
			return nctx.ebpf.AddAllowedHost(ip, e.Key.Port, prio)
		})
		if err != nil {
			m.logger.Error("add joiner ip allow", "container", containerID, "ip", e.Key.IP, "port", e.Key.Port, "error", err)

			continue
		}

		addedAllow = append(addedAllow, e.Key)
	}

	nctx.joinerAllow[containerID] = addedAllow

	return denyErr
}

// removeJoinerIPRules reverses addJoinerIPRules. Idempotent: called on
// Detach for every container, including those that never added any
// entries. A key shared with another container stays in the map (with
// the remaining owners' best priority); only the last owner's removal
// deletes it. Caller must hold Manager.mu.
func (m *Manager) removeJoinerIPRules(nctx *NetnsContext, containerID string) {
	for _, k := range nctx.joinerDeny[containerID] {
		ip := net.ParseIP(k.IP)
		if ip == nil {
			continue
		}

		err := nctx.denyOwners.ownedRemove(k, containerID,
			func(prio uint32) error { return nctx.ebpf.AddDeniedIP(ip, k.Port, prio) },
			func() error { return nctx.ebpf.RemoveDeniedIP(ip, k.Port) },
		)
		if err != nil {
			m.logger.Warn("remove joiner deny", "container", containerID, "ip", k.IP, "port", k.Port, "error", err)
		}
	}

	delete(nctx.joinerDeny, containerID)

	for _, k := range nctx.joinerAllow[containerID] {
		ip := net.ParseIP(k.IP)
		if ip == nil {
			continue
		}

		err := nctx.allowOwners.ownedRemove(k, containerID,
			func(prio uint32) error { return nctx.ebpf.AddAllowedHost(ip, k.Port, prio) },
			func() error { return nctx.ebpf.RemoveAllowedHost(ip, k.Port) },
		)
		if err != nil {
			m.logger.Warn("remove joiner ip allow", "container", containerID, "ip", k.IP, "port", k.Port, "error", err)
		}
	}

	delete(nctx.joinerAllow, containerID)
}

// seedSinkholeDeny installs the always-present sinkhole IP into a
// freshly-loaded eBPF map. The sinkhole (192.0.2.1) is where the DNS
// proxy points blocked A responses; connect attempts to it get dropped
// and tagged as sinkhole_hit. Owned by the netns lifetime (netnsOwner),
// not by any joiner — survives sibling detach, and a joiner rule for
// the same key can neither lower nor delete it.
func (m *Manager) seedSinkholeDeny(nctx *NetnsContext) error {
	sinkIP := net.ParseIP(SinkholeIPv4)
	if sinkIP == nil {
		return nil
	}

	if nctx.denyOwners == nil {
		nctx.denyOwners = make(ipOwners)
	}

	key := ipRuleKey{IP: sinkIP.String(), Port: 0}

	err := nctx.denyOwners.ownedPut(key, netnsOwner, policy.SystemRulePriority, func(prio uint32) error {
		return nctx.ebpf.AddDeniedIP(sinkIP, 0, prio)
	})
	if err != nil {
		m.logger.Warn("seed sinkhole deny", "error", err)

		return fmt.Errorf("seed sinkhole deny: %w", err)
	}

	return nil
}

//nolint:funlen // sequential setup + per-step timings, splitting obscures the rollback chain
func (m *Manager) initNetnsContext(nctx *NetnsContext, pid int, pol *policy.ResolvedPolicy) error {
	overallStart := time.Now()

	auditMode := pol.Action == policy.ActionAudit
	nctx.primaryPID = pid
	nctx.effective = pol
	nctx.auditMode.Store(auditMode)
	nctx.dnsCache = NewDNSCache()
	nctx.sharedDNSRecorder = NewViolationRecorder(nctx.dnsCache)
	nctx.sharedDNSRecorder.SetEnvNamesEnricher(m.EnvNamesFn)

	// Step 1: Load eBPF (without cgroup attachment).
	stepStart := time.Now()

	ebpfHandle, err := m.platform.LoadEBPF(auditMode, m.trustedCIDRs)
	if err != nil {
		return fmt.Errorf("load ebpf: %w", err)
	}

	loadEBPFMs := time.Since(stepStart).Milliseconds()

	nctx.ebpf = ebpfHandle

	// Sinkhole survives joiner detach — it's netns-lifetime, not
	// joiner-owned. Joiner-specific deny IPs (including the creator's
	// own) are installed separately via addJoinerIPRules so Detach can
	// reverse them.
	//
	// In block mode a missing sinkhole deny means blocked DNS answers
	// point at an address the datapath does not drop: fail the creator.
	if seedErr := m.seedSinkholeDeny(nctx); seedErr != nil && !auditMode {
		_ = ebpfHandle.Close()

		return seedErr
	}

	// Step 2: Bind sockets inside the container netns.
	stepStart = time.Now()

	udpConn, tcpListener, err := m.platform.BindInNetns(pid, "127.0.0.1:15353")
	if err != nil {
		_ = ebpfHandle.Close()

		return fmt.Errorf("bind dns proxy in netns: %w", err)
	}

	bindInNetnsMs := time.Since(stepStart).Milliseconds()

	// Step 2.5: Docker mode — create marked upstream socket to Docker DNS.
	if m.IsDocker {
		du, dialErr := m.platform.DialUpstreamInNetns(pid, "127.0.0.11:53", agentMark)
		if dialErr != nil {
			m.logger.Warn("docker upstream socket failed, falling back to host DNS", "error", dialErr)
		} else {
			nctx.dockerUpstream = du
		}
	}

	// Step 3: Set up nftables DNS redirect in container netns.
	stepStart = time.Now()

	setupErr := m.platform.SetupDNSRedirect(pid)
	if setupErr != nil {
		if nctx.dockerUpstream != nil {
			_ = nctx.dockerUpstream.Close()
		}

		if udpConn != nil {
			_ = udpConn.Close()
		}

		if tcpListener != nil {
			_ = tcpListener.Close()
		}

		_ = ebpfHandle.Close()

		return fmt.Errorf("setup nftables: %w", setupErr)
	}

	setupDNSRedirectMs := time.Since(stepStart).Milliseconds()

	// Step 4: Create and start DNS proxy with shared DNS recorder.
	// DNS activity from all sibling containers lands in sharedDNSRecorder.
	proxyCfg := &DNSProxyConfig{
		Policy:         pol,
		Upstreams:      m.upstreams,
		LookupRecorder: nctx.lookupDNSRecorder,
		Logger:         m.logger,
		AddToAllowMap:  ebpfHandle.AddAllowedIP,
		AgentVersion:   m.AgentVersion,
		// Gate the `attached` reply on egress being linked (set by
		// attachPodLink for K8s pods, attachEnforcer for non-pod). Closes
		// the race where the signal fires before AttachCgroup.
		EgressReady: nctx.egressAttached.Load,
	}

	if nctx.dockerUpstream != nil {
		proxyCfg.DockerUpstream = nctx.dockerUpstream
		proxyCfg.DockerUpstreamMu = &sync.Mutex{}
	}

	if m.dnsPIDTracker != nil {
		proxyCfg.LookupDNSPID = m.dnsPIDTracker.LookupWithBinary
	}

	nctx.dnsProxy = NewDNSProxy(proxyCfg)
	nctx.dnsProxy.Start(udpConn, tcpListener)

	// Step 5: Start ringbuf reader for eBPF packet drop events.
	// Packet violations go to per-cgroup recorders for correct attribution.
	// Each drop_event carries its own pid/comm/binary_path from sk_storage
	// populated at LSM socket_connect — no secondary lookup needed.
	stepStart = time.Now()

	stopRingbuf, err := ebpfHandle.StartRingbufReader(
		context.Background(), nctx.lookupPacketRecorder, &nctx.auditMode)
	if err != nil {
		nctx.dnsProxy.Stop()

		_ = m.platform.RemoveDNSRedirect(pid)
		_ = ebpfHandle.Close()

		return fmt.Errorf("start ringbuf reader: %w", err)
	}

	startRingbufMs := time.Since(stepStart).Milliseconds()

	nctx.stopRingbuf = stopRingbuf

	m.logger.Info("netns context initialized",
		"netns_inode", nctx.inode,
		"pid", pid,
		"action", pol.Action,
		"duration_ms", time.Since(overallStart).Milliseconds(),
		"load_ebpf_ms", loadEBPFMs,
		"bind_netns_ms", bindInNetnsMs,
		"setup_dns_redirect_ms", setupDNSRedirectMs,
		"start_ringbuf_ms", startRingbufMs,
	)

	return nil
}

//nolint:funlen // sequential register-recorder + LSM + DNS + timing fields; tight coupling to nctx state
func (m *Manager) attachEnforcer(info ContainerInfo, pid int, pol *policy.ResolvedPolicy, nctx *NetnsContext) (*Enforcer, error) {
	start := time.Now()

	// Resolve cgroup path.
	cgroupPath := info.CgroupPath
	if cgroupPath == "" {
		var err error

		cgroupPath, err = m.platform.GetCgroupPath(pid)
		if err != nil {
			return nil, fmt.Errorf("get cgroup path: %w", err)
		}
	}

	// Remember the original (leaf) path before scope-stripping so we
	// can register its cgroup_id in the LSM and DNS-PID maps. Both
	// BPF programs read bpf_get_current_cgroup_id() which returns
	// the leaf, not the attach point — admitting only the scope id
	// would miss the main process's own events.
	originalCgroupPath := cgroupPath
	cgroupPath = containerScopeCgroup(cgroupPath)

	info.Action = pol.Action
	info.StartedAt = time.Now()

	// In pod-attached mode (K8s sandbox-driven attach), the pod cgroup
	// already covers every container in the pod — skip the per-container
	// attach. Recorder registration and sock_attr LSM tracking below stay
	// per-container because attribution must remain at the leaf cgroup.
	var cgroupLink CgroupLink

	m.mu.Lock()
	podAttached := nctx.podAttached
	m.mu.Unlock()

	if !podAttached {
		var attachErr error

		cgroupLink, attachErr = nctx.ebpf.AttachCgroup(cgroupPath)
		if attachErr != nil {
			return nil, fmt.Errorf("attach cgroup: %w", attachErr)
		}
	}

	// Get the cgroup ID for attribution.
	cgID, err := m.platform.CgroupID(cgroupPath)
	if err != nil {
		if cgroupLink != nil {
			_ = cgroupLink.Close()
		}

		return nil, fmt.Errorf("get cgroup id: %w", err)
	}

	recorder := NewViolationRecorder(nctx.dnsCache)
	recorder.SetEnvNamesEnricher(m.EnvNamesFn)

	// Register recorder in the shared context.
	nctx.mu.Lock()
	nctx.cgroupRecorders[cgID] = recorder
	nctx.pids[info.ContainerID] = pid
	nctx.mu.Unlock()

	// Increment refcount under Manager lock (after all fallible ops).
	m.mu.Lock()
	nctx.refcount++
	m.mu.Unlock()

	// Cgroup IDs to register in the LSM + DNS-PID BPF maps. Always
	// includes the BPF attach point (scope) inode. When scope-stripping
	// was applied we also add the original /init leaf so the main
	// process's own events pass both gates (it reports leaf cgroup_id
	// from the kernel, not the attach point's).
	relevantPaths := []string{cgroupPath}
	if originalCgroupPath != cgroupPath {
		relevantPaths = append(relevantPaths, originalCgroupPath)
	}

	var (
		dnsPIDCgroupIDs   []uint64
		sockAttrCgroupIDs []uint64
	)

	for _, p := range relevantPaths {
		// Register cgroup with DNS PID tracker.
		if m.dnsPIDTracker != nil {
			addedID, addErr := m.dnsPIDTracker.AddCgroup(p)
			if addErr != nil {
				m.logger.Warn("dns pid tracker: failed to add cgroup", "path", p, "error", addErr)
			} else {
				dnsPIDCgroupIDs = append(dnsPIDCgroupIDs, addedID)
			}
		}

		// Register cgroup with sock_attr LSM filter so its sockets
		// populate sk_storage. No-op when LSM attach failed at agent
		// startup (degraded mode — egress falls back to
		// bpf_get_current_* for attribution).
		pathID := cgID

		if p != cgroupPath {
			pid, idErr := m.platform.CgroupID(p)
			if idErr != nil {
				m.logger.Warn("sock_attr: failed to stat leaf cgroup",
					"path", p, "error", idErr)

				continue
			}

			pathID = pid
		}

		sockAttrErr := nctx.ebpf.AddSockKnownCgroup(pathID)
		if sockAttrErr != nil {
			m.logger.Warn("sock_attr: failed to register cgroup",
				"cgroup_id", pathID, "error", sockAttrErr)

			continue
		}

		sockAttrCgroupIDs = append(sockAttrCgroupIDs, pathID)
	}

	e := &Enforcer{
		info:              info,
		policy:            pol,
		cgroup:            cgroupPath,
		cgroupPaths:       relevantPaths,
		pid:               pid,
		logger:            m.logger.With("container_id", truncID(info.ContainerID)),
		ctx:               nctx,
		cgroupLink:        cgroupLink,
		cgroupID:          cgID,
		recorder:          recorder,
		sockAttrCgroupIDs: sockAttrCgroupIDs,
		dnsPIDCgroupIDs:   dnsPIDCgroupIDs,
	}

	// attach_path: ground-truth signal for "are we doing single pod-level
	// attach in K8s?" Three buckets:
	//   pod_attached              — sandbox path engaged, AttachCgroup skipped
	//   per_container_k8s_fallback — K8s shape but pod-attach didn't engage
	//                                (the case Phase 2 cleanup is gated on)
	//   per_container_non_k8s     — Docker / Podman / plain ctr (expected)
	attachPath := "per_container_non_k8s"

	switch {
	case podAttached:
		attachPath = "pod_attached"
	default:
		_, podErr := PodCgroupFromContainer(cgroupPath)
		if podErr == nil {
			attachPath = "per_container_k8s_fallback"

			m.logger.Warn("container attached per-container despite K8s pod shape (pod-attach didn't engage)",
				"container_id", truncID(info.ContainerID),
				"cgroup", cgroupPath,
			)
		}
	}

	e.logger.Info("enforcement attached",
		"project", pol.ProjectPath,
		"action", pol.Action,
		"rules", len(pol.RulesForJob("")),
		"cgroup", cgroupPath,
		"attach_path", attachPath,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return e, nil
}

// inheritProjectInfo returns an info value where project-attribution
// fields fall back to the netns-wide primary when the enforcer's own
// info is unattributed. Mirrors the inheritance rule used by Detach so
// bucket reports and final reports describe the same job.
func inheritProjectInfo(info ContainerInfo, nctx *NetnsContext) ContainerInfo {
	if info.ProjectPath != "" || nctx == nil {
		return info
	}

	nctx.mu.RLock()
	stored := nctx.projectInfo
	nctx.mu.RUnlock()

	if stored.ProjectPath == "" {
		return info
	}

	info.ProjectPath = stored.ProjectPath
	info.JobID = stored.JobID
	info.PipelineID = stored.PipelineID
	info.GitRef = stored.GitRef
	info.JobURL = stored.JobURL
	info.JobName = stored.JobName
	info.JobStage = stored.JobStage
	info.PipelineSrc = stored.PipelineSrc

	return info
}

// runPacketBucketReporter periodically flushes the per-cgroup ViolationRecorder
// (eBPF packet violations) and reports them via ReportFunc. One goroutine per container.
func (m *Manager) runPacketBucketReporter(ctx context.Context, e *Enforcer) {
	defer close(e.packetFlushDone)

	ticker := time.NewTicker(m.BucketInterval)
	defer ticker.Stop()

	var inFlight atomic.Bool

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if inFlight.Load() {
				m.logger.Debug("packet bucket report still in-flight, skipping tick",
					"container_id", truncID(e.info.ContainerID))

				continue
			}

			violations, _, overflow := e.recorder.SnapshotAndReset()
			if len(violations) == 0 && overflow == 0 {
				continue
			}

			// Siblings (init-permissions, service containers) attach
			// without project attribution. By the time this ticker
			// fires the build container has usually joined the netns
			// and populated nctx.projectInfo — inherit from there, so
			// packet buckets flushed from a sibling enforcer still
			// carry a ProjectPath. Without this the report marshals
			// with empty ProjectPath, the server rejects it with
			// InvalidArgument, and the drain queue stays poisoned.
			info := inheritProjectInfo(e.info, e.ctx)
			if info.ProjectPath == "" {
				// Still no attribution — probably a sibling that
				// outlived its netns's build container, or never had
				// one. Drop the bucket silently; emitting an empty
				// report would only wedge the drain queue.
				m.logger.Debug("skipping packet bucket flush — no project attribution",
					"container_id", truncID(e.info.ContainerID))

				continue
			}

			bucketTS := time.Now().Truncate(m.BucketInterval)
			stats := &EgressStats{
				Violations:    violations,
				OverflowCount: overflow,
			}

			inFlight.Store(true)
			m.inFlightReports.Add(1)

			// Use context.Background — the in-flight report must complete even
			// if the ticker context is cancelled during Detach.
			go func() { //nolint:contextcheck,gosec // intentional: report outlives ticker goroutine
				defer inFlight.Store(false)
				defer m.inFlightReports.Done()

				m.ReportFunc(context.Background(), info, stats, true, bucketTS)
			}()
		}
	}
}

// runDNSBucketReporter periodically flushes the shared DNS recorder and reports
// DNS activity. One goroutine per NetnsContext (not per container).
func (m *Manager) runDNSBucketReporter(ctx context.Context, nctx *NetnsContext) {
	defer close(nctx.dnsFlushDone)

	ticker := time.NewTicker(m.BucketInterval)
	defer ticker.Stop()

	var inFlight atomic.Bool

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if inFlight.Load() {
				m.logger.Debug("DNS bucket report still in-flight, skipping tick")

				continue
			}

			violations, activity, overflow := nctx.sharedDNSRecorder.SnapshotAndReset()
			if len(activity) == 0 && len(violations) == 0 {
				continue
			}

			// Read current container info atomically.
			infoPtr := nctx.dnsContainerInfo.Load()
			if infoPtr == nil {
				continue
			}

			info := *infoPtr

			bucketTS := time.Now().Truncate(m.BucketInterval)
			stats := &EgressStats{
				DNSActivity:   activity,
				Violations:    violations,
				OverflowCount: overflow,
			}

			inFlight.Store(true)
			m.inFlightReports.Add(1)

			// Use context.Background — the in-flight report must complete even
			// if the ticker context is cancelled during Detach.
			go func() { //nolint:contextcheck,gosec // intentional: report outlives ticker goroutine
				defer inFlight.Store(false)
				defer m.inFlightReports.Done()

				m.ReportFunc(context.Background(), info, stats, true, bucketTS)
			}()
		}
	}
}

// startPacketBucketReporter starts the per-container packet flush goroutine if bucketing is enabled.
func (m *Manager) startPacketBucketReporter(e *Enforcer) {
	if m.BucketInterval == 0 || m.ReportFunc == nil {
		return
	}

	e.recorder.SetBucketMode()

	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel stored in e.packetFlushCancel, called in Detach
	e.packetFlushCancel = cancel
	e.packetFlushDone = make(chan struct{})

	go m.runPacketBucketReporter(ctx, e)
}

// startDNSBucketReporter starts the per-netns DNS flush goroutine if bucketing is
// enabled and a primary container with ProjectPath is available.
func (m *Manager) startDNSBucketReporter(info ContainerInfo, nctx *NetnsContext) {
	if m.BucketInterval == 0 || m.ReportFunc == nil {
		return
	}

	if info.ProjectPath == "" {
		return
	}

	// Update the atomic pointer so the DNS goroutine attributes reports correctly.
	nctx.dnsContainerInfo.Store(&info)

	if !nctx.dnsFlushStarted.CompareAndSwap(false, true) {
		// Already running — just update container info (done above).
		return
	}

	nctx.sharedDNSRecorder.SetBucketMode()

	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel stored in nctx.dnsFlushCancel, called in Detach
	nctx.dnsFlushCancel = cancel
	nctx.dnsFlushDone = make(chan struct{})

	go m.runDNSBucketReporter(ctx, nctx)
}

// deferredTeardown waits for the grace period then tears down the netns context
// if no new containers joined. This handles the K8s init container lifecycle where
// init-permissions exits before the build container starts.
//
// Aborts immediately if shutdownCh is closed (DetachAll), so an in-flight
// grace period doesn't hold the process open past SIGTERM.
func (m *Manager) deferredTeardown(nctx *NetnsContext) {
	timer := time.NewTimer(m.NetnsGrace)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-m.shutdownCh:
		return
	}

	m.mu.Lock()
	if nctx.refcount > 0 || nctx.tornDown {
		// A sibling joined during the grace period, or another deferred goroutine
		// already tore this context down.
		m.mu.Unlock()

		return
	}

	nctx.tornDown = true

	if nctx.inode != 0 {
		delete(m.netnsContexts, nctx.inode)
	}

	m.mu.Unlock()

	// Stop DNS bucket flush goroutine if still running (grace period expired).
	if nctx.dnsFlushCancel != nil && nctx.dnsFlushStarted.Load() {
		nctx.dnsFlushCancel()
		<-nctx.dnsFlushDone
		nctx.dnsFlushStarted.Store(false)
	}

	// WARN-level so operators can correlate "init-container exited but
	// build-container never attached" failures with grace-period
	// expiry. If you see this paired with missed enforcement, raise
	// LEITWACHT_CE_NETNS_GRACE.
	m.logger.Warn("netns context torn down after grace period — any sibling that joins now will lose audit-mode rules from this netns",
		"netns_inode", nctx.inode,
		"grace", m.NetnsGrace,
	)
	m.teardownNetnsContext(nctx)
}

func (m *Manager) teardownNetnsContext(nctx *NetnsContext) {
	if nctx.dnsProxy != nil {
		nctx.dnsProxy.Stop()
	}

	if nctx.dockerUpstream != nil {
		_ = nctx.dockerUpstream.Close()
	}

	if nctx.stopRingbuf != nil {
		nctx.stopRingbuf()
	}

	// Close pod-cgroup link before the eBPF handle. Errors (e.g., ENOENT
	// when the kernel already cleaned up because the pod cgroup was
	// deleted) are swallowed — there's nothing actionable.
	if nctx.podCgroupLink != nil {
		_ = nctx.podCgroupLink.Close()
		nctx.podCgroupLink = nil
	}

	_ = m.platform.RemoveDNSRedirect(nctx.primaryPID)

	if nctx.ebpf != nil {
		_ = nctx.ebpf.Close()
	}
}

// lsmCgroupPaths returns the cgroup paths to register with the LSM
// known_containers maps: scope and leaf.
func (e *Enforcer) lsmCgroupPaths() []string {
	if len(e.cgroupPaths) > 0 {
		return e.cgroupPaths
	}

	return []string{e.cgroup}
}

// Detach stops enforcement for a container and returns collected stats + original context.
//
//nolint:cyclop,funlen // inherent to teardown + grace period + project inheritance logic
func (m *Manager) Detach(containerID string) *DetachResult {
	start := time.Now()

	m.mu.Lock()
	e, ok := m.enforcers[containerID]
	delete(m.enforcers, containerID)
	delete(m.passive, containerID)

	if !ok || e == nil {
		m.mu.Unlock()

		return nil
	}

	nctx := e.ctx
	nctx.refcount--
	teardown := nctx.refcount == 0

	// Reverse this container's contribution to the eBPF deny map so a
	// later sibling with a different policy doesn't inherit it. Done
	// under m.mu (same lock that guards joinerDeny). The sinkhole entry
	// is owned by the netns lifetime and survives.
	m.removeJoinerIPRules(nctx, containerID)

	// Recompute the strictest-member policy so a departing enforcing
	// member does not leave its siblings under its mode (or a departing
	// audit member leave them weaker than the survivors require).
	if m.removeNetnsMember(nctx, containerID) {
		m.reconcileNetnsPolicy(nctx)
	}

	// When refcount hits 0, don't tear down immediately — sibling containers
	// (e.g., build after init-permissions) may join within seconds. Keep the
	// netns context in the map and schedule deferred teardown.
	lastContainer := teardown // true when this is the last container (refcount==0)

	// Drop the DNS-derived allow entries with the last container. They
	// carry the priority of the rule that authorised them, and a job
	// joining during the grace period brings a different rule list —
	// leaving them would let one job's stale allow outrank another
	// job's deny. No container remains that needs them.
	if lastContainer && nctx.ebpf != nil {
		if err := nctx.ebpf.FlushAllowedIPs(); err != nil {
			m.logger.Warn("flush dns allow map", "container", containerID, "error", err)
		}
	}

	if teardown && nctx.inode != 0 && m.NetnsGrace > 0 {
		go m.deferredTeardown(nctx)

		teardown = false // defer teardown, don't do it inline
	} else if teardown && nctx.inode != 0 {
		delete(m.netnsContexts, nctx.inode)
	}

	// Also clean up cgroup-to-container mappings while we hold m.mu.
	delete(m.credwatchCgroupToContainer, e.cgroupID)
	delete(m.procMemCgroupMap, e.cgroupID)

	// Read stats while m.mu is held so a concurrent teardown from another
	// sibling cannot close the eBPF handle out from under us.
	var totalBytes int64
	if nctx.ebpf != nil {
		totalBytes = nctx.ebpf.ReadStats()
	}

	m.mu.Unlock()

	// Cancel and wait for the per-container packet flush goroutine.
	// This must happen AFTER m.mu.Unlock() but BEFORE the snapshot,
	// so the goroutine is guaranteed stopped and no concurrent flush races.
	if e.packetFlushCancel != nil {
		e.packetFlushCancel()
		<-e.packetFlushDone
	}

	// If this is the last container in the netns (including grace-deferred),
	// stop the DNS flush goroutine so the final snapshot captures all data.
	// Without this, the flush goroutine's SnapshotAndReset can clear the
	// recorder before Detach reads it — causing empty reports for short jobs.
	if lastContainer && nctx.dnsFlushCancel != nil {
		nctx.dnsFlushCancel()
		<-nctx.dnsFlushDone
		nctx.dnsFlushStarted.Store(false)
	}

	// Update primaryPID outside m.mu to avoid holding both locks.
	// Uses nctx.mu write lock since we're writing primaryPID.
	if !teardown {
		nctx.mu.Lock()

		for cID, p := range nctx.pids {
			if cID != containerID {
				nctx.primaryPID = p

				break
			}
		}

		nctx.mu.Unlock()
	}

	// Snapshot per-cgroup recorder (eBPF packet violations).
	// Use SnapshotAndReset when bucketing is active to get final unflushed data.
	packetViolations, _, packetOverflow := e.recorder.SnapshotAndReset()

	// Siblings (init-permissions, services) inherit project info from
	// the first container that provided it — typically the build
	// container that joined the same netns.
	info := inheritProjectInfo(e.info, nctx)

	violations := packetViolations

	var activity []DNSActivityEntry

	var dnsOverflow int64

	if info.ProjectPath != "" {
		var dnsViolations []Violation

		if lastContainer {
			// Last container (immediate teardown or grace-deferred) — take final
			// SnapshotAndReset. DNS flush goroutine is already stopped above.
			dnsViolations, activity, dnsOverflow = nctx.sharedDNSRecorder.SnapshotAndReset()
		} else {
			// Sibling still running — read-only snapshot.
			dnsViolations, activity = nctx.sharedDNSRecorder.Snapshot()
		}

		violations = append(violations, dnsViolations...)
	}

	// Close this container's cgroup link.
	if e.cgroupLink != nil {
		_ = e.cgroupLink.Close()
	}

	// Unregister recorder from shared context.
	nctx.mu.Lock()
	delete(nctx.cgroupRecorders, e.cgroupID)
	delete(nctx.pids, containerID)
	nctx.mu.Unlock()

	// Remove cgroups from DNS PID tracker (scope + any leaf
	// registered alongside it during scope-stripping).
	if m.dnsPIDTracker != nil {
		for _, id := range e.dnsPIDCgroupIDs {
			m.dnsPIDTracker.RemoveCgroup(id)
		}
	}

	// Remove cgroups from sock_attr LSM filter. Existing sk_storage
	// entries for those cgroups' sockets stay valid until the kernel
	// destroys each socket — the filter just stops accepting new
	// captures.
	for _, id := range e.sockAttrCgroupIDs {
		nctx.ebpf.RemoveSockKnownCgroup(id)
	}

	if teardown {
		// Last container in the pod — tear down the shared context.
		m.teardownNetnsContext(nctx)
	}

	// Remove credwatch/proc_mem entries for this container.
	m.DetachCredwatch(containerID)
	m.DetachProcMem(containerID)

	e.logger.Info("enforcement detached",
		"violations", len(violations),
		"dns_entries", len(activity),
		"bytes_sent", totalBytes,
		"teardown", teardown,
		"last_container", lastContainer,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return &DetachResult{
		Info: info,
		Stats: EgressStats{
			TotalBytesSent: totalBytes,
			DNSActivity:    activity,
			Violations:     violations,
			OverflowCount:  packetOverflow + dnsOverflow,
		},
	}
}

// IsEnforced returns true if a container has active (non-nil) enforcement.
// Returns false for nil sentinel slots (attach in progress).
func (m *Manager) IsEnforced(containerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.enforcers[containerID]

	return ok && e != nil
}

// Count returns the number of currently enforced containers.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.enforcers)
}

// DetachAll detaches all active enforcers. Used during graceful shutdown
// to clean up eBPF programs and nftables rules so containers recover DNS.
func (m *Manager) DetachAll() []*DetachResult {
	// Signal background goroutines (deferredTeardown grace periods) to
	// abort. sync.Once so calling DetachAll twice doesn't panic on
	// double-close.
	m.shutdownChOnce.Do(func() { close(m.shutdownCh) })

	m.mu.Lock()

	ids := make([]string, 0, len(m.enforcers))
	for id := range m.enforcers {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	var results []*DetachResult

	for _, id := range ids {
		if r := m.Detach(id); r != nil {
			results = append(results, r)
		}
	}

	// Tear down any pod-sandbox-anchored NetnsContexts that have no
	// remaining real containers. These exist when a sandbox started but
	// no user container ever attached (misconfigured pod, agent shutting
	// down during pod startup, or test fixtures). Without this, the DNS
	// proxy + ringbuf reader goroutines leak past Manager lifetime.
	m.mu.Lock()

	orphans := make([]*NetnsContext, 0, len(m.netnsContexts))

	for ino, nctx := range m.netnsContexts {
		// A deferredTeardown goroutine may be mid-Sleep on this nctx;
		// claim it under m.mu so the goroutine sees tornDown=true on
		// wake and returns without double-closing the eBPF/proxy/ringbuf.
		if nctx.tornDown {
			continue
		}

		nctx.tornDown = true

		orphans = append(orphans, nctx)

		delete(m.netnsContexts, ino)
	}

	m.mu.Unlock()

	for _, nctx := range orphans {
		if nctx.dnsFlushCancel != nil && nctx.dnsFlushStarted.Load() {
			nctx.dnsFlushCancel()
			<-nctx.dnsFlushDone
			nctx.dnsFlushStarted.Store(false)
		}

		m.teardownNetnsContext(nctx)
	}

	// Bound shutdown by BucketInterval (or a sane floor) so in-flight
	// bucket-flush ReportFunc goroutines can finish before the daemon
	// exits. Without this, kubelet SIGKILLs the agent at
	// terminationGracePeriodSeconds with reports mid-POST and the
	// final-bucket data is lost. Default floor of 5s covers tests where
	// BucketInterval is 0 (bucketing disabled).
	wait := m.BucketInterval
	if wait <= 0 {
		wait = 5 * time.Second
	}

	done := make(chan struct{})
	go func() {
		m.inFlightReports.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(wait):
		m.logger.Warn("DetachAll timed out waiting for in-flight bucket reports", "wait", wait)
	}

	return results
}
