package enforcer

import (
	"context"
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

var (
	// ErrNetnsInodeZero is returned when the netns inode resolves to zero.
	ErrNetnsInodeZero = errors.New("netns inode is zero")
	// ErrMaxConcurrent is returned when the max concurrent enforcement limit is reached.
	ErrMaxConcurrent = errors.New("max concurrent enforcement reached")
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

	ebpf           EBPFHandle
	dnsProxy       *DNSProxy
	stopRingbuf    func()
	dockerUpstream *net.UDPConn // pre-bound marked socket for Docker DNS; nil on K8s

	refcount        int                           // protected by Manager.mu
	cgroupRecorders map[uint64]*ViolationRecorder // cgroup_id -> per-container recorder
	pids            map[string]int                // containerID -> pid, for primaryPID update

	// joinerDeny tracks which deny-map entries each joiner contributed
	// so Detach can reverse them. Without this, two siblings of the
	// same netns with disjoint deny lists union over the netns
	// lifetime — an "allow" job inheriting deny IPs from a previous
	// "block" sibling once per-job rule sets land. The sinkhole IP is
	// owned by the netns init, not a joiner, and lives outside this map.
	// Protected by Manager.mu (same as refcount).
	joinerDeny map[string][]denyKey // containerID -> entries

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

	ctx            *NetnsContext // back-ref to shared netns context
	cgroupLink     CgroupLink    // this container's cgroup attachment
	cgroupID       uint64        // for attribution + cgroupRecorders key
	recorder       *ViolationRecorder
	dnsPIDCgroupID uint64 // cgroup ID registered with DNS PID tracker (0 = not registered)

	// Per-container packet bucket flush goroutine.
	packetFlushCancel context.CancelFunc
	packetFlushDone   chan struct{}
}

// Manager tracks all active enforcers across containers.
type Manager struct {
	mu sync.Mutex
	// containerID → Enforcer (nil sentinel during in-flight Attach).
	enforcers map[string]*Enforcer
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

	// BuildKit monitor (global, attach-once at startup).
	buildkit *BuildkitMonitor

	// Honeypot LSM (global, not per-container).
	// Fields used by honeypot_linux.go; appear unused on non-linux builds.
	honeypotCfg       HoneypotConfig
	lsmLoaded         bool                               //nolint:unused,nolintlint // used in honeypot_linux.go (linux-only build tag)
	honeypotState     any                                //nolint:unused,nolintlint // *honeypotLSMImpl on Linux
	honeypotStop      func()                             //nolint:unused,nolintlint // stops ring buffer reader
	containers        map[string]*honeypotContainerState // containerID → tracked state
	cgroupToContainer map[uint64]string                  // cgroupID → containerID (for event resolution)
	OnHoneypotEvent   func(event HoneypotEvent)          // callback for kill + report

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

// NewManager creates an enforcement manager with the given configuration.
func NewManager(
	logger *slog.Logger, maxConcurrent int, upstreams []string,
	trustedCIDRs []net.IPNet, platform Platform, honeypotCfg HoneypotConfig,
) *Manager {
	return &Manager{
		enforcers:         make(map[string]*Enforcer),
		netnsContexts:     make(map[uint64]*NetnsContext),
		logger:            logger,
		maxConc:           maxConcurrent,
		upstreams:         upstreams,
		trustedCIDRs:      trustedCIDRs,
		platform:          platform,
		honeypotCfg:       honeypotCfg,
		containers:        make(map[string]*honeypotContainerState),
		cgroupToContainer: make(map[uint64]string),
		shutdownCh:        make(chan struct{}),
	}
}

// SetBuildkit configures the BuildKit monitor. Must be called before any Attach calls.
func (m *Manager) SetBuildkit(bm *BuildkitMonitor) {
	m.buildkit = bm
}

// Attach sets up enforcement for a container. Sibling containers in the same
// pod (same netns) share a single NetnsContext (DNS proxy, nftables, eBPF
// objects) but each get their own cgroup attachment and ViolationRecorder.
func (m *Manager) Attach(_ context.Context, info ContainerInfo, pid int, pol *policy.ResolvedPolicy) (*Enforcer, error) {
	if pol.Action == "allow" {
		m.logger.Info("skipping enforcement (allow mode)", "container_id", info.ContainerID[:12])

		return nil, nil //nolint:nilnil // nil,nil signals "skip, no error"
	}

	netnsIno, netnsErr := m.platform.NetnsInode(pid)
	if netnsErr != nil {
		m.logger.Warn("netns inode lookup failed; using standalone context",
			"container_id", info.ContainerID[:12],
			"pid", pid,
			"error", netnsErr,
		)

		netnsIno = 0
	}

	m.mu.Lock()

	if len(m.enforcers) >= m.maxConc {
		m.mu.Unlock()
		m.logger.Warn("max concurrent enforcement reached, skipping",
			"container_id", info.ContainerID[:12],
			"max", m.maxConc,
		)

		return nil, nil //nolint:nilnil // nil,nil signals "skip, no error"
	}

	if _, exists := m.enforcers[info.ContainerID]; exists {
		m.mu.Unlock()
		m.logger.Warn("container already enforced, skipping duplicate",
			"container_id", info.ContainerID[:12],
		)

		return nil, nil //nolint:nilnil // nil,nil signals "skip, no error"
	}

	m.enforcers[info.ContainerID] = nil
	m.mu.Unlock()

	releaseSlot := func() {
		m.mu.Lock()
		delete(m.enforcers, info.ContainerID)
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

	// Both creator and joiner paths register their deny IPs through
	// the same per-container ownership map so Detach can reverse them.
	// The sinkhole entry is netns-lifetime and was seeded once during
	// initNetnsContext.
	m.mu.Lock()
	m.addJoinerDenyIPs(nctx, info.ContainerID, pol)
	m.mu.Unlock()

	if !created {
		// Joiner-only: swap DNS proxy policy and flip eBPF mode if
		// needed. Creator already installed both during initNetnsContext.
		m.applyJoinerPolicy(info, nctx, pol)
	}

	e, attachErr := m.attachEnforcer(info, pid, pol, nctx)
	if attachErr != nil {
		releaseSlot()

		// Creator owns the netns context: failed attachEnforcer means
		// no other container is using it yet, so tear it down rather
		// than leaving an orphan. Joiners share the context with at
		// least one already-attached sibling, so leaving it alone is
		// correct (the existing sibling keeps using it).
		if created {
			m.mu.Lock()
			if netnsIno != 0 {
				delete(m.netnsContexts, netnsIno)
			}
			m.mu.Unlock()

			m.teardownNetnsContext(nctx)
		}

		return nil, attachErr
	}

	m.finalizeAttach(info, e, nctx) //nolint:contextcheck // bucket reporters use context.Background() intentionally — outlive caller

	return e, nil
}

// applyJoinerPolicy reconciles a NetnsContext that was already
// initialised by an earlier (audit-all) creator with the joiner's real
// policy: swap the DNS proxy policy and flip eBPF mode if the action
// differs. Deny-IP installation happens earlier in Attach (under
// Manager.mu) so this function does not touch the deny map itself.
func (m *Manager) applyJoinerPolicy(info ContainerInfo, nctx *NetnsContext, pol *policy.ResolvedPolicy) {
	if nctx.dnsProxy != nil {
		nctx.dnsProxy.UpdatePolicy(pol)
	}

	joinerAudit := pol.Action == policy.ActionAudit
	if joinerAudit == nctx.auditMode.Load() {
		return
	}

	modeErr := nctx.ebpf.SetMode(joinerAudit)
	if modeErr != nil {
		m.logger.Error("update ebpf mode on sibling join", "error", modeErr)

		return
	}

	// Store only after SetMode succeeds: the kernel and the ringbuf
	// reader's view must not disagree on what mode is in effect.
	nctx.auditMode.Store(joinerAudit)
	m.logger.Info("ebpf mode updated on sibling join",
		"container_id", info.ContainerID[:12],
		"audit", joinerAudit,
	)
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

	e, attachErr := m.attachEnforcer(
		ContainerInfo{ContainerID: containerID, CgroupPath: cgroupPath},
		pid, auditPol, nctx,
	)
	if attachErr != nil {
		releaseSlot()

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

	if created {
		m.logger.Info("netns prepared for sibling",
			"container_id", containerID[:12],
			"netns_inode", netnsIno,
		)
	} else {
		m.logger.Info("sibling joined existing netns",
			"container_id", containerID[:12], "netns_inode", netnsIno)
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
// honeypot inodes. Common to both creator and joiner paths in Attach.
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

	m.attachBuildkit(info.ContainerID, nctx, e)
	m.startPacketBucketReporter(e)
	m.startDNSBucketReporter(info, nctx)
	m.AttachHoneypot(info.ContainerID, e.cgroup)
}

// denyKey identifies one entry in the eBPF deny map.
type denyKey struct {
	IP   string
	Port int
}

// addJoinerDenyIPs installs a joiner's policy deny IPs and records
// ownership so the entries can be reversed at Detach. Caller must hold
// Manager.mu (same lock as nctx.refcount / joinerDeny).
//
// The sinkhole IP is seeded once per netns by seedSinkholeDeny — it is
// not owned by any joiner and survives joiner detach.
func (m *Manager) addJoinerDenyIPs(nctx *NetnsContext, containerID string, pol *policy.ResolvedPolicy) {
	if nctx.joinerDeny == nil {
		nctx.joinerDeny = make(map[string][]denyKey)
	}

	added := nctx.joinerDeny[containerID][:0]

	for _, dip := range pol.DenyIPs {
		ip := net.ParseIP(dip.IP)
		if ip == nil {
			continue
		}

		if err := nctx.ebpf.AddDeniedIP(ip, dip.Port); err != nil {
			m.logger.Warn("add joiner deny", "container", containerID, "ip", dip.IP, "port", dip.Port, "error", err)

			continue
		}

		added = append(added, denyKey{IP: dip.IP, Port: dip.Port})
	}

	nctx.joinerDeny[containerID] = added
}

// removeJoinerDenyIPs reverses addJoinerDenyIPs. Idempotent: called on
// Detach for every container, including those that never added any
// entries. Caller must hold Manager.mu.
func (m *Manager) removeJoinerDenyIPs(nctx *NetnsContext, containerID string) {
	entries, ok := nctx.joinerDeny[containerID]
	if !ok {
		return
	}

	for _, k := range entries {
		ip := net.ParseIP(k.IP)
		if ip == nil {
			continue
		}

		if err := nctx.ebpf.RemoveDeniedIP(ip, k.Port); err != nil {
			m.logger.Warn("remove joiner deny", "container", containerID, "ip", k.IP, "port", k.Port, "error", err)
		}
	}

	delete(nctx.joinerDeny, containerID)
}

// seedSinkholeDeny installs the always-present sinkhole IP into a
// freshly-loaded eBPF map. The sinkhole (192.0.2.1) is where the DNS
// proxy points blocked A responses; connect attempts to it get dropped
// and tagged as sinkhole_hit. Owned by the netns lifetime, not by any
// joiner — survives sibling detach.
func (m *Manager) seedSinkholeDeny(handle EBPFHandle) {
	sinkIP := net.ParseIP(SinkholeIPv4)
	if sinkIP == nil {
		return
	}

	if err := handle.AddDeniedIP(sinkIP, 0); err != nil {
		m.logger.Warn("seed sinkhole deny", "error", err)
	}
}

//nolint:funlen // sequential setup + per-step timings, splitting obscures the rollback chain
func (m *Manager) initNetnsContext(nctx *NetnsContext, pid int, pol *policy.ResolvedPolicy) error {
	overallStart := time.Now()

	auditMode := pol.Action == policy.ActionAudit
	nctx.primaryPID = pid
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
	// own) are installed separately via addJoinerDenyIPs so Detach can
	// reverse them.
	m.seedSinkholeDeny(ebpfHandle)

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

	cgroupPath = containerScopeCgroup(cgroupPath)

	info.Action = pol.Action
	info.StartedAt = time.Now()

	// In pod-attached mode (K8s sandbox-driven attach), the pod cgroup
	// already covers every container in the pod — skip the per-container
	// attach. Recorder registration and sock_attr LSM tracking below stay
	// per-container because attribution must remain at the leaf cgroup.
	var cgroupLink CgroupLink

	if !nctx.podAttached {
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

	// Register cgroup with DNS PID tracker.
	var dnsPIDCgroupID uint64

	if m.dnsPIDTracker != nil {
		addedID, addErr := m.dnsPIDTracker.AddCgroup(cgroupPath)
		if addErr != nil {
			m.logger.Warn("dns pid tracker: failed to add cgroup", "error", addErr)
		} else {
			dnsPIDCgroupID = addedID
		}
	}

	// Register cgroup with sock_attr LSM filter so its sockets populate
	// sk_storage. No-op when LSM attach failed at agent startup (degraded
	// mode — egress falls back to bpf_get_current_* for attribution).
	sockAttrErr := nctx.ebpf.AddSockKnownCgroup(cgID)
	if sockAttrErr != nil {
		m.logger.Warn("sock_attr: failed to register cgroup",
			"cgroup_id", cgID, "error", sockAttrErr)
	}

	e := &Enforcer{
		info:           info,
		policy:         pol,
		cgroup:         cgroupPath,
		pid:            pid,
		logger:         m.logger.With("container_id", info.ContainerID[:12]),
		ctx:            nctx,
		cgroupLink:     cgroupLink,
		cgroupID:       cgID,
		recorder:       recorder,
		dnsPIDCgroupID: dnsPIDCgroupID,
	}

	// attach_path: ground-truth signal for "are we doing single pod-level
	// attach in K8s?" Three buckets:
	//   pod_attached              — sandbox path engaged, AttachCgroup skipped
	//   per_container_k8s_fallback — K8s shape but pod-attach didn't engage
	//                                (the case Phase 2 cleanup is gated on)
	//   per_container_non_k8s     — Docker / Podman / plain ctr (expected)
	attachPath := "per_container_non_k8s"

	switch {
	case nctx.podAttached:
		attachPath = "pod_attached"
	default:
		_, podErr := PodCgroupFromContainer(cgroupPath)
		if podErr == nil {
			attachPath = "per_container_k8s_fallback"

			m.logger.Warn("container attached per-container despite K8s pod shape (pod-attach didn't engage)",
				"container_id", info.ContainerID[:12],
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

// attachBuildkit attaches the buildkit cgroup to the job's eBPF program and
// registers the buildkit cgroupID in the netns context's recorder map.
// Non-fatal: failures are logged but don't prevent job enforcement.
func (m *Manager) attachBuildkit(containerID string, nctx *NetnsContext, e *Enforcer) {
	if m.buildkit == nil {
		return
	}

	// Only attach buildkit for containers with project attribution (build containers).
	if e.info.ProjectPath == "" {
		return
	}

	// DNS proxy queries must land on sharedDNSRecorder — that's the recorder the
	// bucket reporter snapshots for DNS activity. Packet drops stay on the
	// per-container recorder via cgroupRecorders below.
	attached, err := m.buildkit.AttachJob(containerID, nctx.ebpf, nctx.sharedDNSRecorder, e.policy)
	if err != nil {
		m.logger.Warn("buildkit attach failed", "error", err)

		return
	}

	if !attached {
		return
	}

	// Register buildkit cgroupID in the netns context so the ring buffer reader
	// can attribute buildkit packet drops to this job's recorder.
	nctx.mu.Lock()
	nctx.cgroupRecorders[m.buildkit.CgroupID()] = e.recorder
	nctx.mu.Unlock()
}

// detachBuildkit begins buildkit drain and unregisters from cgroupRecorders.
func (m *Manager) detachBuildkit(containerID string, nctx *NetnsContext) {
	if m.buildkit == nil {
		return
	}

	m.buildkit.DetachJob(containerID)

	// Unregister buildkit cgroupID from the recorder map.
	// The drain timer in BuildkitMonitor keeps the cgroup link alive —
	// the recorder entry is removed here to prevent misattribution if a
	// new job starts before drain completes (the new job will re-register).
	nctx.mu.Lock()
	delete(nctx.cgroupRecorders, m.buildkit.CgroupID())
	nctx.mu.Unlock()
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
					"container_id", e.info.ContainerID[:12])

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
					"container_id", e.info.ContainerID[:12])

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

// Detach stops enforcement for a container and returns collected stats + original context.
//
//nolint:cyclop,funlen // inherent to teardown + grace period + project inheritance logic
func (m *Manager) Detach(containerID string) *DetachResult {
	start := time.Now()

	m.mu.Lock()
	e, ok := m.enforcers[containerID]
	delete(m.enforcers, containerID)

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
	m.removeJoinerDenyIPs(nctx, containerID)

	// When refcount hits 0, don't tear down immediately — sibling containers
	// (e.g., build after init-permissions) may join within seconds. Keep the
	// netns context in the map and schedule deferred teardown.
	lastContainer := teardown // true when this is the last container (refcount==0)

	if teardown && nctx.inode != 0 && m.NetnsGrace > 0 {
		go m.deferredTeardown(nctx)

		teardown = false // defer teardown, don't do it inline
	} else if teardown && nctx.inode != 0 {
		delete(m.netnsContexts, nctx.inode)
	}

	// Also clean up cgroup-to-container mapping while we hold m.mu.
	delete(m.cgroupToContainer, e.cgroupID)

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

	// Begin buildkit drain (keeps cgroup link + recorder alive for tail traffic).
	m.detachBuildkit(containerID, nctx)

	// Close this container's cgroup link.
	if e.cgroupLink != nil {
		_ = e.cgroupLink.Close()
	}

	// Unregister recorder from shared context.
	nctx.mu.Lock()
	delete(nctx.cgroupRecorders, e.cgroupID)
	delete(nctx.pids, containerID)
	nctx.mu.Unlock()

	// Remove cgroup from DNS PID tracker.
	if m.dnsPIDTracker != nil && e.dnsPIDCgroupID != 0 {
		m.dnsPIDTracker.RemoveCgroup(e.dnsPIDCgroupID)
	}

	// Remove cgroup from sock_attr LSM filter. Existing sk_storage
	// entries for that cgroup's sockets stay valid until the kernel
	// destroys each socket — the filter just stops accepting new
	// captures.
	nctx.ebpf.RemoveSockKnownCgroup(e.cgroupID)

	if teardown {
		// Last container in the pod — tear down the shared context.
		m.teardownNetnsContext(nctx)
	}

	// Remove honeypot inode entries for this container.
	m.DetachHoneypot(containerID)

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

	// Close buildkit monitor after all enforcers are detached.
	if m.buildkit != nil {
		m.buildkit.Close()
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
