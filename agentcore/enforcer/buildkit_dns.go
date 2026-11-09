// Package enforcer — build DNS proxy.
//
// BuildKit RUN steps of a default-network buildkitd share the buildkitd
// pod's netns and resolve through the cluster DNS. Name (FQDN) rules are
// enforced for them by an agent DNS proxy bound inside that netns on a
// loopback address, reached by a transparent redirect: cgroup sock_addr
// programs (connect4, sendmsg4, recvmsg4) attached at the BuildKit cgroup
// parent rewrite UDP/TCP port-53 destinations of RUN cgroups to the proxy
// and rewrite UDP reply sources back, so neither resolv.conf nor
// buildkitd's configuration changes (BuildKit strips loopback
// nameservers from RUN resolv.conf anyway, so a proxy address there would
// never be used).
//
// Per query the proxy learns the RUN cgroup from the dns_pid kprobes
// (subtree form: every task below a registered BuildKit parent is
// tracked, recorded against its RUN cgroup), asks the BuildPolicyBinder
// for that cgroup's decision, and answers per policy:
//
//   - bound, enforce: name rules apply as for a job pod. Allowed answers
//     seed the cgroup's slot (bk_dns_sets), denied names get the rule's
//     resolution (sinkhole / NXDOMAIN), unmatched names the sinkhole;
//   - bound, shadow: answered normally, a would-be denial is recorded as
//     dns_would_block; allowed answers still seed;
//   - everything else (audit, pending, ambiguous, unattributed, degraded,
//     queries from outside any RUN cgroup): answered normally and
//     recorded as dns_observed. Never fail-closed.
//
// While a RUN cgroup is still PENDING and an enforce policy is in play the
// answer is held until the join binds it or the deadline passes (design
// section 3), then given per policy, or in audit when never bound.
//
// Lifecycle: the proxy follows the buildkitd process. When the process
// (or its netns) changes it is rebound; while it is not bound the redirect
// is off, DNS goes straight to the upstream (which the port-53 pin
// allows), and rows of policies with name rules carry
// fqdn_rules_inactive. CNI/bridge-mode buildkitd (a netns per RUN) is not
// supported: a RUN whose netns differs from the proxy's turns the redirect
// off and domain rules stay inactive (IP rules still apply).

package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

const (
	// DefaultBuildDNSListen is where the build DNS proxy listens inside
	// the buildkitd netns. Loopback is allowed by the egress filter before
	// the port-53 pin, and is reachable from RUN steps that share the
	// netns.
	DefaultBuildDNSListen = "127.0.0.153:15354"

	// DefaultBuildDNSProc is the process name the default netns source
	// looks for.
	DefaultBuildDNSProc = "buildkitd"

	defaultBuildDNSPoll = 500 * time.Millisecond

	// maxBuildDNSHolds bounds the queries held at once so a burst from
	// fresh cgroups cannot exhaust the proxy's in-flight budget; beyond
	// it queries are answered immediately (audit).
	maxBuildDNSHolds = 64

	// maxHoldsPerCgroup bounds the queries one RUN cgroup can hold, so a
	// step cannot use up the global budget; maxInflightPerCgroup and the
	// rate limit below keep one step from filling the proxy's in-flight
	// budget (maxInflightQueries) and SERVFAILing every other build.
	// maxInflightPerProject keeps the steps of one project (policy key
	// project; unbound and unattributed steps are not capped) from
	// using more than a quarter of the proxy's shared in-flight budget
	// (maxInflightQueries, 256): it takes at least four projects acting
	// together to starve the others, instead of eight steps of one.
	maxInflightPerProject = 64

	probeName     = "probe.lw-build-dns.invalid."
	probeTimeout  = time.Second
	probeInterval = 5 * time.Second

	maxHoldsPerCgroup    = 8
	maxInflightPerCgroup = 32
	// The rate limit only bounds the load one step can put on the
	// upstream and the proxy; the in-flight cap above is what keeps one
	// step from filling the shared budget. It counts every query (not
	// only forwarded ones: that would need the answer path to report back)
	// and is set high enough that ndots-expanded lookup bursts of a
	// package install (several short-circuited names per lookup) stay far
	// below it.
	queryRatePerSec = 1000.0
	queryBurst      = 2000.0

	// latchHold is how long a CNI / flap latch keeps the redirect off
	// before the netns is evaluated again; maxProofRebinds in
	// proofRebindWindow is the flap threshold.
	latchHold         = 10 * time.Minute
	maxProofRebinds   = 3
	proofRebindWindow = 5 * time.Minute
	maxLimiters       = 4096

	// maxFirstSeen bounds the hold's per-cgroup first-query stamps.
	maxFirstSeen = 4096

	maxDomainCgroups      = 1024
	maxDomainsPerCgroup   = 256
	domainRetention       = 15 * time.Minute
	searchListRefreshTime = 30 * time.Second
	bindErrLogInterval    = 30 * time.Second

	// maxPendingRecs bounds the per-cgroup recorders that hold the DNS
	// activity of RUN cgroups not yet bound to a policy; past it activity
	// goes to the shared recorder. pendingRehomeGrace is how long such a
	// recorder waits for its cgroup to be bound before it is emitted
	// unattributed (a slow join may bind after the first flush).
	maxPendingRecs = 1024
	// maxPendingEntries caps the (domain, type) entries of one pending
	// recorder; past it the activity goes to the shared recorder.
	maxPendingEntries  = 256
	pendingRehomeGrace = 10 * time.Second

	// Event-driven bind: after a new RUN cgroup appears, its cgroup.procs
	// is read every runEventRetryEvery for up to runEventRetries tries
	// (runc adds the first process a moment after the mkdir).
	runEventRetries    = 50
	runEventRetryEvery = 2 * time.Millisecond
)

// BuildDNSTracker is the DNS attribution source of the build proxy. It is
// implemented by *DNSPIDTracker.
type BuildDNSTracker interface {
	// AddRunParent registers a BuildKit parent cgroup: queries from any
	// task below it are attributed to the RUN cgroup.
	AddRunParent(cgroupID uint64) error
	RemoveRunParent(cgroupID uint64)
	// LookupWithBinary attributes a query by (netns cookie, source port).
	LookupWithBinary(netnsCookie uint64, srcPort uint16) (pid uint32, comm, parentComm, binaryPath string, cgroupID uint64)
}

// BuildDNSConfig configures the build DNS proxy (WithBuildKitDNSProxy).
type BuildDNSConfig struct {
	// Tracker attributes queries to RUN cgroups. Required: without it the
	// proxy cannot tell RUN steps apart and is not started.
	Tracker BuildDNSTracker
	// NetnsPID returns the PID of a process in the netns the RUN steps
	// run in. Polled; a change of the netns rebinds the proxy. It must be
	// trustworthy: a CI job controls its own processes' names and can run
	// a buildkitd or dind of its own. Default: a live process inside a RUN
	// cgroup under the configured BuildKit parents (they share buildkitd's
	// netns in host network mode), else, when ProcCgroupContains is set, a
	// process named ProcName whose cgroup path contains it. Never a name
	// match alone. Until a trusted netns is known the redirect stays off
	// (DNS goes to the upstream: fail-open).
	NetnsPID func() (int, error)
	// ProcName narrows the ProcCgroupContains lookup (default
	// "buildkitd"); it is never trusted by itself.
	ProcName string
	// ProcCgroupContains identifies the buildkitd pod, letting the proxy
	// bind before the first RUN step exists: a full pod UID (8-4-4-4-12
	// hex; "-" or "_") that must occur in the process's cgroup path, or an
	// absolute cgroup path that must equal it or be an ancestor of it.
	// Anything else is rejected. It breaks when the pod is recreated
	// unless updated, and the proxy already stays bound between build
	// steps, so leave it empty unless the first build after an agent or
	// buildkitd start must be enforced.
	ProcCgroupContains string
	// ListenAddr is the proxy address inside the netns (host:port, IPv4;
	// default DefaultBuildDNSListen).
	ListenAddr string
	// Upstreams are the resolvers queries are forwarded to (host:port or
	// bare IPv4; port 53 is assumed). Default: the attach's DNS
	// upstreams (WithBuildKitDNSUpstreams).
	Upstreams []string
	// ClusterDomain and ExpansionSuppression behave as for the per-pod
	// proxy (search-list expansions of public names are answered NXDOMAIN
	// locally instead of sinkholed). The search list is buildkitd's
	// resolv.conf, which RUN steps inherit.
	ClusterDomain        string
	ExpansionSuppression string
	// CacheSize is the positive-answer cache capacity (0 disables).
	CacheSize int
	// PollInterval is how often the RUN processes' netns is re-checked
	// (default 500ms).
	PollInterval time.Duration
	// HoldWindow bounds the DNS hold of a PENDING RUN cgroup (default
	// DefaultSynHoldWindow, the joiner's deadline).
	HoldWindow time.Duration
	// ProcRoot is the /proc mount (default /proc).
	ProcRoot string
	// ProbeInterval is how often the proxy is queried through its own
	// netns to detect a hung listener (default 5s).
	ProbeInterval time.Duration
}

// runSample is one live RUN-cgroup process and the netns it is in.
type runSample struct {
	pid int
	ino uint64
}

// WithBuildKitDNSProxy enables the build DNS proxy so name rules apply
// to RUN steps. See the file comment. Requires the slot datapath, the
// policy binder (a registry) and cgroup sock_addr support; otherwise it
// is skipped with a warning and name rules stay inactive.
func WithBuildKitDNSProxy(c BuildDNSConfig) BuildKitAttachOption {
	return func(cfg *buildKitAttachConfig) { cfg.dnsProxy = &c }
}

// buildDNS is the running build DNS proxy.
type buildDNS struct {
	// afterSnapshotHook is a test-only hook run in drainPending after a
	// recorder snapshot and before the delete check (nil in production).
	afterSnapshotHook func(id uint64)

	cfg    BuildDNSConfig
	log    *slog.Logger
	dp     BuildKitDatapath
	binder *BuildPolicyBinder
	main   *ViolationRecorder

	parents   []uint64
	runPaths  []string
	listenIP  net.IP
	listenPrt uint16

	bind       func(pid int, addr string) (net.PacketConn, net.Listener, error)
	netnsInode func(pid int) (uint64, error)
	// sample lists the live RUN-cgroup processes with their netns inodes.
	sample func() []runSample
	// anyInNetns reports whether any process on the host is still in the
	// netns with the given inode (a /proc scan, only done when a RUN
	// process shows up in a different netns).
	anyInNetns func(ino uint64) bool
	// newDialer opens a handle on a netns that outlives its processes; the
	// liveness probe sends its query through it.
	newDialer func(pid int) (UpstreamDialer, error)
	dialer    UpstreamDialer

	// newSource builds the cgroup-creation watcher on the RUN parents that
	// triggers an immediate bind (tests replace it).
	newSource func(paths []string) CgroupEventSource
	watchDone chan struct{}

	cache    *dnsCache
	auditCfg *DNSProxyConfig
	auditPol *policy.ResolvedPolicy

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	holds chan struct{}

	mu       sync.Mutex // guards the lifecycle fields below and the maps
	proxy    *DNSProxy
	boundPID int
	boundIno uint64
	enabled  bool
	// verified: a live RUN-cgroup process was seen in the bound netns;
	// the redirect is never enabled before that, and once verified it
	// stays on while the proxy is bound (the proxy's own sockets keep the
	// netns alive), also between build steps. mismatch latches (for
	// latchHold) when RUN processes are seen in several netns (CNI/bridge
	// mode) or the netns keeps changing from step to step (rebind flap);
	// the redirect is off meanwhile.
	verified   bool
	mismatch   bool
	latchUntil time.Time
	proofBinds []time.Time
	lastErr    string
	lastErrT   time.Time

	// Per-cgroup isolation: holds in progress, in-flight queries and a
	// token bucket per cgroup (0 = unattributed shares one).
	projInflight map[string]int
	cgHolds      map[uint64]int
	limiters     map[uint64]*cgLimiter
	seeded       map[uint64]string // cgroup -> policy id its recorded names were last seeded under

	firstSeen map[uint64]time.Time
	slotCfgs  map[slotCfgKey]*slotCfg
	recs      map[PolicyKey]*ViolationRecorder
	// pend holds the DNS activity of cgroups that had no bound policy at
	// query time, per cgroup, so DrainDNS can re-home it to the policy the
	// cgroup was bound to since.
	pend map[uint64]*pendingRec

	searchMu  sync.Mutex
	search    []string
	searchAt  time.Time
	searchPID int

	domains *buildDomains

	closeOnce sync.Once
}

type pendingRec struct {
	rec      *ViolationRecorder
	since    time.Time
	last     time.Time // last query; the decision is looked up as of this time
	inflight int       // queries that hold rec and have not recorded yet
}

type slotCfgKey struct {
	slot     uint32
	policyID string
	mode     uint8
}

type slotCfg struct {
	cfg *DNSProxyConfig
	pol *policy.ResolvedPolicy
}

var (
	errBuildDNSNoTracker = errors.New("build dns proxy needs the dns pid tracker")
	errBuildDNSProcGone  = errors.New("buildkitd process not found")
)

// startBuildDNS validates cfg, registers the RUN parents with the tracker
// and starts following the buildkitd process. It returns (nil, nil) when
// the proxy cannot run in this deployment (logged), so the attach goes on
// without name enforcement.
func startBuildDNS(
	parent context.Context,
	cfg BuildDNSConfig,
	log *slog.Logger,
	platform Platform,
	dp BuildKitDatapath,
	binder *BuildPolicyBinder,
	main *ViolationRecorder,
	parents []uint64,
	runPaths []string,
	attachUpstreams []net.IP,
) (*buildDNS, error) {
	if binder == nil {
		log.Warn("buildkit dns proxy not started: no policy binder (needs the session registry); domain rules are not enforced for build steps")

		return nil, nil //nolint:nilnil // documented: not started
	}

	if !dp.DNSRedirectAvailable() {
		log.Warn("buildkit dns proxy not started: cgroup sock_addr redirect programs are not attached; domain rules are not enforced for build steps")

		return nil, nil //nolint:nilnil // documented: not started
	}

	if cfg.Tracker == nil {
		log.Warn("buildkit dns proxy not started: dns pid tracker unavailable; domain rules are not enforced for build steps")

		return nil, nil //nolint:nilnil // documented: not started
	}

	d, err := newBuildDNS(cfg, log, dp, binder, main, parents, runPaths, attachUpstreams)
	if err != nil {
		return nil, err
	}

	d.bind = platform.BindInNetns
	d.netnsInode = platform.NetnsInode
	d.newDialer = platform.NewUpstreamDialer

	for _, id := range parents {
		if addErr := cfg.Tracker.AddRunParent(id); addErr != nil {
			for _, done := range parents {
				if done == id {
					break
				}

				cfg.Tracker.RemoveRunParent(done)
			}

			return nil, fmt.Errorf("register buildkit parent for dns attribution: %w", addErr)
		}
	}

	d.start(parent)

	return d, nil
}

func newBuildDNS(
	cfg BuildDNSConfig, log *slog.Logger, dp BuildKitDatapath, binder *BuildPolicyBinder, main *ViolationRecorder,
	parents []uint64, runPaths []string, attachUpstreams []net.IP,
) (*buildDNS, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultBuildDNSListen
	}

	host, portStr, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("build dns listen %q: %w", cfg.ListenAddr, err)
	}

	ip := net.ParseIP(host).To4()

	port, perr := strconv.ParseUint(portStr, 10, 16)
	if ip == nil || perr != nil || port == 0 {
		return nil, fmt.Errorf("%w: build dns listen %q must be an IPv4 address and port", errBKConfigRange, cfg.ListenAddr)
	}

	if len(cfg.Upstreams) == 0 {
		for _, u := range attachUpstreams {
			cfg.Upstreams = append(cfg.Upstreams, u.String())
		}
	}

	for i, u := range cfg.Upstreams {
		if _, _, splitErr := net.SplitHostPort(u); splitErr != nil {
			cfg.Upstreams[i] = net.JoinHostPort(strings.TrimSpace(u), "53")
		}
	}

	if err = validateProcCgroup(cfg.ProcCgroupContains); err != nil {
		return nil, err
	}

	if cfg.ProcName == "" {
		cfg.ProcName = DefaultBuildDNSProc
	}

	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}

	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = probeInterval
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultBuildDNSPoll
	}

	if cfg.HoldWindow <= 0 {
		cfg.HoldWindow = DefaultSynHoldWindow
	}

	if cfg.ClusterDomain == "" {
		cfg.ClusterDomain = DefaultClusterDomain
	}

	d := &buildDNS{
		cfg:          cfg,
		log:          log,
		dp:           dp,
		binder:       binder,
		main:         main,
		parents:      parents,
		runPaths:     runPaths,
		listenIP:     ip,
		listenPrt:    uint16(port),
		cache:        newDNSCache(cfg.CacheSize),
		auditPol:     &policy.ResolvedPolicy{Action: policy.ActionAudit},
		holds:        make(chan struct{}, maxBuildDNSHolds),
		firstSeen:    map[uint64]time.Time{},
		cgHolds:      map[uint64]int{},
		projInflight: map[string]int{},
		limiters:     map[uint64]*cgLimiter{},
		seeded:       map[uint64]string{},
		slotCfgs:     map[slotCfgKey]*slotCfg{},
		recs:         map[PolicyKey]*ViolationRecorder{},
		pend:         map[uint64]*pendingRec{},
		domains:      newBuildDomains(),
		newSource:    func(paths []string) CgroupEventSource { return NewInotifyCgroupSource(paths) },
	}

	d.auditCfg = d.newCfg(nil, false)
	d.sample = d.defaultSample
	d.anyInNetns = d.defaultAnyInNetns

	return d, nil
}

// candidatePID picks the process whose netns a new proxy binds in: a live
// RUN-cgroup process (trusted: it runs under the configured BuildKit
// parent), else a cgroup-matched buildkitd when ProcCgroupContains is set.
// A process name alone is never enough. fromRun tells which.
func (d *buildDNS) candidatePID(samples []runSample) (pid int, fromRun bool) {
	if len(samples) > 0 {
		return samples[0].pid, true
	}

	if d.cfg.ProcCgroupContains != "" {
		if p, err := findTrustedProc(d.cfg.ProcRoot, d.cfg.ProcName, d.cfg.ProcCgroupContains); err == nil {
			return p, false
		}
	}

	return 0, false
}

// newCfg builds a per-policy proxy config for HandleDNSQuery. Seeding is
// done by buildDNS.afterAnswer (it needs the queried name), so
// AddToAllowMap stays nil.
func (d *buildDNS) newCfg(rec *ViolationRecorder, shadow bool) *DNSProxyConfig {
	cfg := &DNSProxyConfig{
		Upstreams: d.cfg.Upstreams,
		Logger:    d.log,
		LookupRecorder: func(uint64) *ViolationRecorder {
			return rec
		},
		SearchListFor:        d.searchListFor,
		ClusterDomain:        d.cfg.ClusterDomain,
		ExpansionSuppression: d.cfg.ExpansionSuppression,
		Shadow:               shadow,
	}
	cfg.cache = d.cache

	return cfg
}

func (d *buildDNS) start(parent context.Context) {
	d.ctx, d.cancel = context.WithCancel(parent)
	d.done = make(chan struct{})

	d.reconcile()

	go d.run()

	if len(d.runPaths) > 0 && d.newSource != nil {
		d.watchDone = make(chan struct{})

		go d.watchRunCgroups()
	}
}

// watchRunCgroups binds the proxy as soon as a RUN cgroup appears instead
// of waiting for the next poll tick: the first step after an agent start
// would otherwise resolve through the cluster DNS unobserved. The poll
// stays as the fallback (and the only path when the watch cannot run).
func (d *buildDNS) watchRunCgroups() {
	defer close(d.watchDone)

	creates := make(chan CgroupCreateEvent, 64)
	removes := make(chan CgroupRemoveEvent, 64)
	src := d.newSource(d.runPaths)

	errc := make(chan error, 1)

	go func() { errc <- src.Run(d.ctx, creates, removes) }()

	for {
		select {
		case <-d.ctx.Done():
			<-errc

			return
		case err := <-errc:
			if err != nil && !errors.Is(err, context.Canceled) {
				d.log.Debug("buildkit dns proxy: cgroup watch stopped; binding by poll only", "error", err)
			}

			return
		case evt, ok := <-creates:
			if !ok {
				creates = nil

				continue
			}

			d.onRunCgroup(evt.CgroupPath)
		case _, ok := <-removes:
			if !ok {
				removes = nil
			}
		}
	}
}

// needsBind reports whether the proxy still has to be bound or verified.
func (d *buildDNS) needsBind() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.proxy == nil || !d.verified
}

// onRunCgroup runs on the watcher goroutine (the only one that reacts to
// events, so reconciles from events never overlap each other). It waits
// briefly for the new cgroup's first process, then reconciles. It does
// nothing when the proxy is already bound and verified.
func (d *buildDNS) onRunCgroup(cgroupPath string) {
	procs := filepath.Join(cgroupPath, "cgroup.procs")

	for i := 0; i < runEventRetries; i++ {
		if d.ctx.Err() != nil || !d.needsBind() {
			return
		}

		if firstProcOf(procs) > 0 {
			d.reconcile()

			return
		}

		time.Sleep(runEventRetryEvery)
	}
}

func (d *buildDNS) run() {
	defer close(d.done)

	t := time.NewTicker(d.cfg.PollInterval)
	defer t.Stop()

	lastProbe := time.Now()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
			d.reconcile()
			d.reseedBound()

			if time.Since(lastProbe) >= d.cfg.ProbeInterval {
				lastProbe = time.Now()

				if !d.probeOnce() {
					d.reconcile() // retry the bind
				}
			}
		}
	}
}

// Close stops the proxy, turns the redirect off and unregisters the RUN
// parents. Safe to call twice.
func (d *buildDNS) Close() {
	d.closeOnce.Do(func() {
		d.cancel()
		<-d.done

		if d.watchDone != nil {
			<-d.watchDone
		}

		d.mu.Lock()
		d.unbindLocked("shutdown")
		d.mu.Unlock()

		for _, id := range d.parents {
			d.cfg.Tracker.RemoveRunParent(id)
		}
	})
}

// reconcile keeps the proxy bound in the RUN steps' netns. The netns comes
// from live RUN-cgroup processes; once it is verified the proxy and the
// redirect stay up for as long as no RUN process proves a different netns,
// so sequential build steps (no RUN process alive in between) never fall
// back to the upstream. A different netns seen alone is treated as a
// buildkitd restart (rebind); several at once, or repeated changes, as
// CNI/bridge mode (latch off). A dead serving goroutine clears the
// redirect first and rebinds.
func (d *buildDNS) reconcile() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// A reconcile that lost the race with Close must not bind again.
	if d.ctx != nil && d.ctx.Err() != nil {
		return
	}

	// Sampled under the lock so concurrent reconciles (poll and event)
	// never act on a stale sample.
	samples := d.sample()

	if d.proxy != nil && !d.proxy.Alive() {
		d.log.Error("buildkit dns proxy: serving goroutine exited; redirect cleared, rebinding")
		d.unbindLocked("proxy goroutine exited")
	}

	if d.mismatch && time.Now().After(d.latchUntil) {
		d.mismatch = false
		d.proofBinds = nil
	}

	if d.cfg.NetnsPID != nil {
		d.reconcileOperatorLocked(samples)

		return
	}

	if d.proxy == nil {
		pid, fromRun := d.candidatePID(samples)
		if pid == 0 {
			return
		}

		if d.bindLocked(pid) {
			d.verified = fromRun
			d.judgeLocked(samples) // latches at once if the RUN steps disagree
		}

		return
	}

	d.judgeLocked(samples)
}

// reconcileOperatorLocked follows an operator-supplied netns source
// (BuildDNSConfig.NetnsPID): its netns is bound, a failure unbinds.
func (d *buildDNS) reconcileOperatorLocked(samples []runSample) {
	pid, err := d.cfg.NetnsPID()
	if err != nil || pid <= 0 {
		d.unbindLocked("buildkitd process not found")

		return
	}

	ino, err := d.netnsInode(pid)
	if err != nil {
		d.unbindLocked("buildkitd netns not readable")

		return
	}

	if d.proxy != nil && ino != d.boundIno {
		d.unbindLocked("buildkitd netns changed")

		d.mismatch = false
		d.proofBinds = nil
	}

	if d.proxy == nil && !d.bindLocked(pid) {
		return
	}

	d.judgeLocked(samples)
}

// judgeLocked compares the RUN processes' netns with the bound one.
func (d *buildDNS) judgeLocked(samples []runSample) {
	var (
		same    bool
		foreign = map[uint64]int{}
	)

	for _, sm := range samples {
		if sm.ino == d.boundIno {
			same = true
			d.boundPID = sm.pid
		} else {
			foreign[sm.ino] = sm.pid
		}
	}

	switch {
	case len(foreign) == 0:
		if same {
			d.verified = true
		}
	case d.mismatch:
		// already latched
	case !same && len(foreign) == 1 && d.cfg.NetnsPID == nil:
		// Only a different netns among the RUN steps. A genuine buildkitd
		// restart leaves nobody in the old netns; a RUN step that did
		// `unshare -n` leaves the real buildkitd (and its other
		// processes) there. Only the former rebinds. The scan is paid
		// only here.
		if d.anyInNetns(d.boundIno) {
			d.rateLimitedErrLocked("a RUN step runs in a different netns while the bound one is still in use (unshare/insecure entitlement?); not rebinding")

			break
		}

		// Rebind, unless this keeps happening (CNI: a netns per step).
		now := time.Now()

		recent := d.proofBinds[:0]

		for _, t := range d.proofBinds {
			if now.Sub(t) < proofRebindWindow {
				recent = append(recent, t)
			}
		}

		d.proofBinds = append(recent, now)
		if len(d.proofBinds) > maxProofRebinds {
			d.latchLocked("the RUN steps' netns keeps changing")

			break
		}

		for _, pid := range foreign {
			d.unbindLocked("a RUN step proved a different netns")

			if d.bindLocked(pid) {
				d.verified = true
			}
		}
	default:
		d.latchLocked("RUN steps run in different netns (CNI or bridge network mode?)")
	}

	d.applyLocked()
}

func (d *buildDNS) latchLocked(why string) {
	if !d.mismatch {
		d.log.Error("buildkit dns proxy: "+why+"; the redirect is off, domain rules are not enforced for build steps, only IP rules apply",
			"proxy_netns_inode", d.boundIno, "retry_after", latchHold.String())
	}

	d.mismatch = true
	d.latchUntil = time.Now().Add(latchHold)
}

// bindLocked binds the proxy in pid's netns. The redirect is not touched.
func (d *buildDNS) bindLocked(pid int) bool {
	ino, err := d.netnsInode(pid)
	if err != nil {
		d.rateLimitedErrLocked(fmt.Sprintf("read netns of pid %d: %v", pid, err))

		return false
	}

	udp, tcp, err := d.bind(pid, d.cfg.ListenAddr)
	if err != nil {
		d.rateLimitedErrLocked(fmt.Sprintf("bind build dns proxy in buildkitd netns: %v", err))

		return false
	}

	proxyCfg := &DNSProxyConfig{
		Policy:       d.auditPol,
		Upstreams:    d.cfg.Upstreams,
		Logger:       d.log,
		LookupDNSPID: d.cfg.Tracker.LookupWithBinary,
		QueryHandler: d.handle,
	}

	p := NewDNSProxy(proxyCfg)
	p.Start(udp, tcp)

	if d.newDialer != nil {
		if dl, derr := d.newDialer(pid); derr == nil {
			d.dialer = dl
		} else {
			d.log.Warn("buildkit dns proxy: cannot open a handle on the netns; liveness probe disabled", "error", derr)
		}
	}

	d.proxy = p
	d.boundPID = pid
	d.boundIno = ino
	d.verified = false
	d.lastErr = ""

	// Read the search list now: the sampled process is often gone by the
	// first query, which would leave expansion suppression without a list.
	d.primeSearchList(pid)

	d.log.Info("buildkit dns proxy bound in the RUN steps' netns", "listen", d.cfg.ListenAddr, "netns_inode", ino)

	return true
}

// applyLocked turns the redirect on or off from the verified / latched
// state: never on before a RUN process was seen in the bound netns, never
// while latched.
func (d *buildDNS) applyLocked() {
	if d.proxy == nil || d.mismatch || !d.verified {
		d.disableLocked()

		return
	}

	if d.enabled {
		return
	}

	cookie := d.proxy.netnsCookie
	if cookie == 0 {
		d.rateLimitedErrLocked("netns cookie of the proxy sockets unavailable")

		return
	}

	if err := d.dp.SetDNSRedirect(d.listenIP, d.listenPrt, cookie, true); err != nil {
		d.rateLimitedErrLocked(fmt.Sprintf("enable build dns redirect: %v", err))

		return
	}

	d.enabled = true
	d.binder.SetDNSProxyActive(true)
}

func (d *buildDNS) disableLocked() {
	if !d.enabled {
		return
	}

	if err := d.dp.SetDNSRedirect(d.listenIP, d.listenPrt, 0, false); err != nil {
		d.log.Error("buildkit dns proxy: cannot turn the redirect off", "error", err)
	}

	d.enabled = false
	d.binder.SetDNSProxyActive(false)
}

// unbindLocked stops the proxy (redirect first, so no query is sent to a
// socket that is about to close).
func (d *buildDNS) unbindLocked(reason string) {
	if d.proxy == nil {
		return
	}

	wasActive := d.enabled

	d.disableLocked()

	d.proxy.Stop()
	d.proxy = nil

	if d.dialer != nil {
		_ = d.dialer.Close()
		d.dialer = nil
	}

	d.boundPID = 0
	d.boundIno = 0

	if wasActive || reason != "shutdown" {
		d.log.Warn("buildkit dns proxy unbound; DNS passes to the upstream and domain rules are not enforced until it is bound again",
			"reason", reason)
	}
}

func (d *buildDNS) rateLimitedErrLocked(msg string) {
	if msg == d.lastErr && time.Since(d.lastErrT) < bindErrLogInterval {
		return
	}

	d.lastErr = msg
	d.lastErrT = time.Now()

	d.log.Error("buildkit dns proxy: "+msg+"; domain rules are not enforced for build steps, only IP rules apply",
		"policy", "fail-open")
}

// runProcs lists up to max PIDs, at most one per RUN cgroup (the first
// of its cgroup.procs), under the RUN-parent paths.
func runProcs(runPaths []string, max int) []int {
	var out []int

	for _, parent := range runPaths {
		kids, err := os.ReadDir(parent)
		if err != nil {
			continue
		}

		for _, kid := range kids {
			if !kid.IsDir() {
				continue
			}

			if pid := firstProcOf(filepath.Join(parent, kid.Name(), "cgroup.procs")); pid > 0 {
				out = append(out, pid)
				if len(out) >= max {
					return out
				}
			}
		}
	}

	return out
}

// defaultSample lists the live RUN processes with their netns inodes.
func (d *buildDNS) defaultSample() []runSample {
	var out []runSample

	for _, pid := range runProcs(d.runPaths, 16) {
		if ino, err := d.netnsInode(pid); err == nil {
			out = append(out, runSample{pid: pid, ino: ino})
		}
	}

	return out
}

func firstProcOf(path string) int {
	f, err := os.Open(path) //nolint:gosec // cgroup.procs of a watched cgroup
	if err != nil {
		return 0
	}

	defer f.Close() //nolint:errcheck // read-only

	buf := make([]byte, 64)

	n, _ := f.Read(buf)

	fields := strings.Fields(string(buf[:n]))
	if len(fields) == 0 {
		return 0
	}

	pid, _ := strconv.Atoi(fields[0])

	return pid
}

var podUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}$`)

// validateProcCgroup accepts a full pod UID or an absolute cgroup path.
func validateProcCgroup(v string) error {
	if v == "" || podUIDRe.MatchString(v) || (strings.HasPrefix(v, "/") && len(v) > 1 && !strings.Contains(v, "..")) {
		return nil
	}

	return fmt.Errorf("%w: ProcCgroupContains %q must be a full pod UID or an absolute cgroup path", errBKConfigRange, v)
}

// cgroupMatches reports whether a /proc/<pid>/cgroup file places the
// process under want: an absolute path equal to (or an ancestor of) the
// process's cgroup path, or a pod UID occurring in it (as written with
// "-" or "_").
func cgroupMatches(content, want string) bool {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}

		path := parts[2]

		if strings.HasPrefix(want, "/") {
			if path == want || strings.HasPrefix(path, strings.TrimSuffix(want, "/")+"/") {
				return true
			}

			continue
		}

		if strings.Contains(path, want) || strings.Contains(path, strings.ReplaceAll(want, "-", "_")) {
			return true
		}
	}

	return false
}

// findTrustedProc returns the lowest PID under procRoot whose comm is name
// and whose cgroup is the operator-configured buildkitd pod's (see
// cgroupMatches). The name alone is forgeable and never enough.
func findTrustedProc(procRoot, name, cgroupWant string) (int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", procRoot, err)
	}

	best := 0

	for _, e := range entries {
		pid, convErr := strconv.Atoi(e.Name())
		if convErr != nil || pid <= 0 || (best != 0 && pid > best) {
			continue
		}

		comm, readErr := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm")) //nolint:gosec // procfs
		if readErr != nil || strings.TrimSpace(string(comm)) != name {
			continue
		}

		cg, readErr := os.ReadFile(filepath.Join(procRoot, e.Name(), "cgroup")) //nolint:gosec // procfs
		if readErr != nil || !cgroupMatches(string(cg), cgroupWant) {
			continue
		}

		best = pid
	}

	if best == 0 {
		return 0, fmt.Errorf("%w: %s", errBuildDNSProcGone, name)
	}

	return best, nil
}

// searchListFor is the search list read from the resolv.conf of the bound
// RUN process (buildkitd generates it from its own, but the step can
// rewrite it, so it is treated as step-controlled), refreshed every
// searchListRefreshTime. That is safe: only an expansion under the
// configured cluster domain (never derived from this list) that the cluster
// DNS confirms as NXDOMAIN is ever dropped; an expansion under any other
// suffix, including one the step injected, is still recorded.
func (d *buildDNS) searchListFor(uint64) []string {
	d.mu.Lock()
	pid := d.boundPID
	d.mu.Unlock()

	d.searchMu.Lock()
	defer d.searchMu.Unlock()

	if pid <= 0 || (d.searchPID == pid && time.Since(d.searchAt) < searchListRefreshTime) {
		return d.search // unbound: the last known list
	}

	// The sampled RUN process may be gone by now (steps are short): keep
	// the last list then.
	if list := readSearchList(d.cfg.ProcRoot, pid); list != nil || d.search == nil {
		d.search = list
	}

	d.searchPID = pid
	d.searchAt = time.Now()

	return d.search
}

// primeSearchList stores the search list of pid's resolv.conf.
func (d *buildDNS) primeSearchList(pid int) {
	list := readSearchList(d.cfg.ProcRoot, pid)

	d.searchMu.Lock()
	defer d.searchMu.Unlock()

	if list != nil || d.search == nil {
		d.search = list
	}

	d.searchPID = pid
	d.searchAt = time.Now()
}

// Active reports whether the redirect is on.
func (d *buildDNS) Active() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.enabled
}

// decide returns the cgroup's decision, holding a PENDING cgroup's answer
// while an enforce policy is in play (bounded in time and in number of
// held queries).
func (d *buildDNS) decide(id uint64) BuildDNSDecision {
	if id == 0 {
		return BuildDNSDecision{}
	}

	dec := d.binder.DNSDecision(id)
	if dec.Known || !d.binder.HoldEnabled() {
		return dec
	}

	deadline := d.firstSeenAt(id).Add(d.cfg.HoldWindow)
	if !time.Now().Before(deadline) {
		return dec
	}

	d.mu.Lock()
	if d.cgHolds[id] >= maxHoldsPerCgroup {
		d.mu.Unlock()

		return dec
	}

	d.cgHolds[id]++
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		if d.cgHolds[id]--; d.cgHolds[id] <= 0 {
			delete(d.cgHolds, id)
		}
		d.mu.Unlock()
	}()

	select {
	case d.holds <- struct{}{}:
		defer func() { <-d.holds }()
	default:
		return dec
	}

	dec = d.binder.WaitDecision(d.ctx, id, deadline)
	if dec.Known {
		d.mu.Lock()
		delete(d.firstSeen, id)
		d.mu.Unlock()
	}

	return dec
}

func (d *buildDNS) firstSeenAt(id uint64) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()

	if t, ok := d.firstSeen[id]; ok {
		return t
	}

	now := time.Now()

	if len(d.firstSeen) >= maxFirstSeen {
		for k, t := range d.firstSeen {
			if now.Sub(t) > time.Minute || len(d.firstSeen) >= maxFirstSeen {
				delete(d.firstSeen, k)
			}
		}
	}

	d.firstSeen[id] = now

	return now
}

// recorderFor is the recorder a decision's DNS activity goes to: one per
// bound policy key (so the entries carry the project); for a cgroup not
// bound yet, one per cgroup so DrainDNS can re-home it once the cgroup is
// bound; the shared one for everything else (unattributed queries, or the
// pending-recorder bound reached).
func (d *buildDNS) recorderFor(dec BuildDNSDecision, cgroupID uint64) (*ViolationRecorder, func()) {
	if !dec.Known || dec.Key.Project == "" || dec.State != bkStateBound {
		if cgroupID == 0 || dec.Known {
			return d.main, noopRelease // ambiguous / unattributed / degraded never re-home
		}

		return d.pendingFor(cgroupID)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	r, ok := d.recs[dec.Key]
	if !ok {
		r = NewViolationRecorder(nil)
		r.SetBucketMode()
		d.recs[dec.Key] = r
	}

	return r, noopRelease
}

func noopRelease() {}

// pendingFor is the per-cgroup recorder of a cgroup with no entry yet. The
// returned release must be called once the query has been recorded: until
// then the drain keeps the recorder alive. Over the recorder or entry caps
// the shared recorder is returned instead (nothing is dropped).
func (d *buildDNS) pendingFor(id uint64) (*ViolationRecorder, func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	p, ok := d.pend[id]
	if !ok {
		if len(d.pend) >= maxPendingRecs {
			return d.main, noopRelease
		}

		r := NewViolationRecorder(nil)
		r.SetBucketMode()

		p = &pendingRec{rec: r, since: now}
		d.pend[id] = p
	} else if p.rec.dnsEntryCount() >= maxPendingEntries {
		return d.main, noopRelease
	}

	p.last = now
	p.inflight++

	return p.rec, func() {
		d.mu.Lock()
		p.inflight--
		d.mu.Unlock()
	}
}

// cfgFor returns the proxy config and policy a decision's queries are
// evaluated under.
func (d *buildDNS) cfgFor(dec BuildDNSDecision, rec *ViolationRecorder) (*DNSProxyConfig, *policy.ResolvedPolicy) {
	if !dec.Enforcing() {
		if rec == d.main {
			return d.auditCfg, d.auditPol
		}

		return d.newCfg(rec, false), d.auditPol
	}

	key := slotCfgKey{slot: dec.slot.idx, policyID: dec.PolicyID, mode: dec.Mode}

	d.mu.Lock()
	defer d.mu.Unlock()

	if sc, ok := d.slotCfgs[key]; ok {
		return sc.cfg, sc.pol
	}

	// Prune configs of slots that no longer exist (bounded by slot count
	// times versions; a stale key is just an unused entry).
	if len(d.slotCfgs) >= 4*bkMaxSlots {
		d.slotCfgs = map[slotCfgKey]*slotCfg{}
	}

	sc := &slotCfg{cfg: d.newCfg(rec, dec.Mode == bkModeShadow), pol: synthPolicy(dec.Rules)}
	d.slotCfgs[key] = sc

	return sc.cfg, sc.pol
}

// synthPolicy builds a ResolvedPolicy whose fqdn rules sit at the list
// positions their priorities encode, so RulePriority(index) equals the
// rule's Prio and HandleDNSQuery needs no changes. Missing positions are
// cidr placeholders (matchFirstRule skips them).
func synthPolicy(rules []BuildFQDNRule) *policy.ResolvedPolicy {
	maxIdx := -1

	for _, r := range rules {
		if idx := int(r.Prio) - 1; idx > maxIdx {
			maxIdx = idx
		}
	}

	list := make([]policy.Rule, maxIdx+1)
	for i := range list {
		list[i] = policy.Rule{PatternType: policy.PatternCIDR}
	}

	for _, r := range rules {
		idx := int(r.Prio) - 1
		if idx < 0 {
			continue
		}

		action := policy.ActionDeny
		if r.Allow {
			action = policy.ActionAllow
		}

		list[idx] = policy.Rule{
			Pattern:     r.Pattern,
			PatternType: policy.PatternFQDN,
			Action:      action,
			Resolution:  r.Resolution,
			Ports:       r.Ports,
		}
	}

	return &policy.ResolvedPolicy{
		Action:   policy.ActionBlock,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": list},
	}
}

// handle answers one query (DNSProxyConfig.QueryHandler).
func (d *buildDNS) handle(msg *dns.Msg, q DNSQueryContext) *dns.Msg {
	if len(msg.Question) == 0 {
		return refusedResponse(msg)
	}

	if canonicalName(msg.Question[0].Name) == canonicalName(probeName) {
		resp := new(dns.Msg) // liveness probe: answered locally, never forwarded
		resp.SetReply(msg)

		return resp
	}

	release, ok := d.admit(q.CgroupID)
	if !ok {
		// One step must not be able to fill the proxy's in-flight budget:
		// over its own limit only that cgroup is refused.
		return refusedResponse(msg)
	}

	defer release()

	dec := d.decide(q.CgroupID)

	releaseProj, ok := d.admitProject(dec.Key.Project)
	if !ok {
		return refusedResponse(msg)
	}

	defer releaseProj()

	rec, releaseRec := d.recorderFor(dec, q.CgroupID)
	defer releaseRec()

	cfg, pol := d.cfgFor(dec, rec)

	resp := HandleDNSQuery(msg, cfg, pol, rec, q.PID, q.Comm, q.ParentComm, q.BinaryPath, q.CgroupID)

	d.afterAnswer(dec, q.CgroupID, msg, resp)

	return resp
}

// afterAnswer seeds the slot for an allowed name and remembers which
// domain the cgroup resolved each IP from.
func (d *buildDNS) afterAnswer(dec BuildDNSDecision, cgroupID uint64, msg, resp *dns.Msg) {
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(msg.Question) == 0 {
		return
	}

	qname := canonicalName(msg.Question[0].Name)
	chain := cnameChain(qname, resp.Answer)

	var ips []net.IP

	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok || !chain[canonicalName(a.Hdr.Name)] {
			continue
		}

		ips = append(ips, a.A)
	}

	if len(ips) == 0 {
		return
	}

	if dec.Enforcing() {
		if rule, matched := matchBuildFQDN(qname, dec.Rules); matched && rule.Allow {
			d.binder.SeedDNS(dec, qname, ips, rule)
		}
	}

	if cgroupID != 0 {
		d.domains.record(cgroupID, qname, ips)

		// The cgroup may have been bound after dec was taken (hold timeout
		// or overflow) and after reseedBound already ran for it: a name
		// recorded now would never be seeded. Re-check and seed directly.
		if !dec.Enforcing() {
			if now := d.binder.DNSDecision(cgroupID); now.Enforcing() {
				if rule, matched := matchBuildFQDN(qname, now.Rules); matched && rule.Allow {
					d.binder.SeedDNS(now, qname, ips, rule)
				}
			}
		}
	}
}

// DrainDNS returns the DNS activity of bound build steps accumulated since
// the last call, stamped with project, job and policy.
func (d *buildDNS) DrainDNS() []DNSActivityEntry {
	d.mu.Lock()

	keys := make([]PolicyKey, 0, len(d.recs))
	for k := range d.recs {
		keys = append(keys, k)
	}

	recs := make([]*ViolationRecorder, len(keys))
	for i, k := range keys {
		recs[i] = d.recs[k]
	}

	d.mu.Unlock()

	var out []DNSActivityEntry

	for i, r := range recs {
		_, entries, _ := r.SnapshotAndReset()
		for _, e := range entries {
			e.BuildProjectPath = keys[i].Project
			e.BuildJobName = keys[i].Job
			e.PolicyKey = keys[i].String()
			out = append(out, e)
		}
	}

	return append(out, d.drainPending()...)
}

// drainPending emits the DNS activity recorded while a cgroup had no bound
// policy. A cgroup bound since is stamped with its policy (the same
// re-keying StampDomains does for egress rows). One still unbound waits up
// to pendingRehomeGrace (the join may bind after this flush), then is
// emitted unattributed like the shared recorder's entries: nothing is
// dropped. At shutdown everything is emitted.
func (d *buildDNS) drainPending() []DNSActivityEntry {
	final := d.ctx != nil && d.ctx.Err() != nil

	d.mu.Lock()

	ids := make([]uint64, 0, len(d.pend))
	recs := make([]*pendingRec, 0, len(d.pend))
	lasts := make([]time.Time, 0, len(d.pend))

	for id, p := range d.pend {
		ids = append(ids, id)
		recs = append(recs, p)
		lasts = append(lasts, p.last)
	}

	d.mu.Unlock()

	var out []DNSActivityEntry

	now := time.Now()

	for i, p := range recs {
		// Also finds a cgroup already removed (short steps end before the
		// flush): the binder keeps its decision for a while.
		dec := d.binder.DNSDecisionAt(ids[i], lasts[i])
		bound := dec.Known && dec.State == bkStateBound && dec.Key.Project != ""

		if !bound && !final && now.Sub(p.since) < pendingRehomeGrace {
			continue
		}

		_, entries, _ := p.rec.SnapshotAndReset()

		if d.afterSnapshotHook != nil {
			d.afterSnapshotHook(ids[i])
		}

		for _, e := range entries {
			if bound {
				e.BuildProjectPath = dec.Key.Project
				e.BuildJobName = dec.Key.Job
				e.PolicyKey = dec.Key.String()
			}

			out = append(out, e)
		}

		d.mu.Lock()
		// Re-checked under the lock: a whole query may have run since the
		// snapshot above; its entry must not go with the recorder.
		if len(entries) == 0 && p.inflight == 0 && p.rec.dnsEntryCount() == 0 {
			if d.pend[ids[i]] == p {
				delete(d.pend, ids[i])
			}
		}
		d.mu.Unlock()
	}

	return out
}

// StampDomains sets Domain (source build_dns_proxy) on rows whose IP the
// row's own RUN cgroup resolved through the proxy.
func (d *buildDNS) StampDomains(violations []Violation) {
	for i := range violations {
		v := &violations[i]
		if v.Domain != "" || v.CgroupID == 0 || v.IP == "" {
			continue
		}

		if name := d.domains.lookup(v.CgroupID, v.IP); name != "" {
			v.Domain = name
			v.DomainSource = DomainSourceBuildDNSProxy
		}
	}
}

// buildDomains is the per-RUN-cgroup IP -> name record of the proxy.
type buildDomains struct {
	mu sync.Mutex
	m  map[uint64]*cgDomains
}

type cgDomains struct {
	ips  map[[4]byte]string
	last time.Time
}

func newBuildDomains() *buildDomains { return &buildDomains{m: map[uint64]*cgDomains{}} }

func (b *buildDomains) record(id uint64, name string, ips []net.IP) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	cg, ok := b.m[id]
	if !ok {
		if len(b.m) >= maxDomainCgroups {
			b.pruneLocked(now)
		}

		cg = &cgDomains{ips: map[[4]byte]string{}}
		b.m[id] = cg
	}

	cg.last = now

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil || ip4.String() == SinkholeIPv4 {
			continue // as the per-pod cache: one address, many blocked names
		}

		var k [4]byte

		copy(k[:], ip4)

		if _, exists := cg.ips[k]; !exists && len(cg.ips) >= maxDomainsPerCgroup {
			continue
		}

		cg.ips[k] = name
	}
}

// pruneLocked drops expired cgroups, then the oldest ones until under the
// cap.
func (b *buildDomains) pruneLocked(now time.Time) {
	for id, cg := range b.m {
		if now.Sub(cg.last) > domainRetention {
			delete(b.m, id)
		}
	}

	if len(b.m) < maxDomainCgroups {
		return
	}

	type idAge struct {
		id uint64
		t  time.Time
	}

	all := make([]idAge, 0, len(b.m))
	for id, cg := range b.m {
		all = append(all, idAge{id, cg.last})
	}

	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })

	for _, a := range all[:len(all)/4+1] {
		delete(b.m, a.id)
	}
}

func (b *buildDomains) lookup(id uint64, ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}

	var k [4]byte

	copy(k[:], p)

	b.mu.Lock()
	defer b.mu.Unlock()

	cg, ok := b.m[id]
	if !ok {
		return ""
	}

	return cg.ips[k]
}

// *DNSPIDTracker is the production tracker.
var _ BuildDNSTracker = (*DNSPIDTracker)(nil)

// cgLimiter is one cgroup's token bucket plus in-flight count.
type cgLimiter struct {
	tokens   float64
	last     time.Time
	inflight int
}

// admit applies the per-cgroup in-flight cap and query rate limit.
func (d *buildDNS) admit(id uint64) (release func(), ok bool) {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	l, found := d.limiters[id]
	if !found {
		if len(d.limiters) >= maxLimiters {
			for k, v := range d.limiters {
				if v.inflight == 0 && now.Sub(v.last) > time.Minute {
					delete(d.limiters, k)
				}
			}
		}

		l = &cgLimiter{tokens: queryBurst, last: now}
		d.limiters[id] = l
	}

	l.tokens = min(queryBurst, l.tokens+now.Sub(l.last).Seconds()*queryRatePerSec)
	l.last = now

	if l.inflight >= maxInflightPerCgroup || l.tokens < 1 {
		return nil, false
	}

	l.tokens--
	l.inflight++

	return func() {
		d.mu.Lock()
		l.inflight--
		d.mu.Unlock()
	}, true
}

// reseedBound re-seeds the slot of every cgroup that has recorded
// answers from the names it resolved before it was bound (hold timeout or
// overflow, then a late bind), against the policy it is bound to now, so
// later connects to allowed names are not dropped for want of a seed.
// Runs on every poll tick; cheap when nothing changed.
func (d *buildDNS) reseedBound() {
	for _, id := range d.domains.ids() {
		dec := d.binder.DNSDecision(id)
		if !dec.Enforcing() {
			continue
		}

		d.mu.Lock()
		same := d.seeded[id] == dec.PolicyID
		d.mu.Unlock()

		if same {
			continue
		}

		for ip, name := range d.domains.snapshot(id) {
			if rule, matched := matchBuildFQDN(name, dec.Rules); matched && rule.Allow {
				d.binder.SeedDNS(dec, name, []net.IP{net.IP(ip[:])}, rule)
			}
		}

		d.mu.Lock()
		if len(d.seeded) >= maxDomainCgroups {
			d.seeded = map[uint64]string{}
		}

		d.seeded[id] = dec.PolicyID
		d.mu.Unlock()
	}
}

func (b *buildDomains) ids() []uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]uint64, 0, len(b.m))
	for id := range b.m {
		out = append(out, id)
	}

	return out
}

func (b *buildDomains) snapshot(id uint64) map[[4]byte]string {
	b.mu.Lock()
	defer b.mu.Unlock()

	cg, ok := b.m[id]
	if !ok {
		return nil
	}

	out := make(map[[4]byte]string, len(cg.ips))
	for k, v := range cg.ips {
		out[k] = v
	}

	return out
}

// defaultAnyInNetns scans /proc/*/ns/net for a process in the netns.
func (d *buildDNS) defaultAnyInNetns(ino uint64) bool {
	entries, err := os.ReadDir(d.cfg.ProcRoot)
	if err != nil {
		return true // cannot tell: assume it is in use (no rebind)
	}

	want := fmt.Sprintf("net:[%d]", ino)

	for _, e := range entries {
		if _, convErr := strconv.Atoi(e.Name()); convErr != nil {
			continue
		}

		link, rerr := os.Readlink(filepath.Join(d.cfg.ProcRoot, e.Name(), "ns", "net"))
		if errors.Is(rerr, os.ErrPermission) {
			return true // cannot see it: treat the netns as in use
		}

		if rerr == nil && link == want {
			return true
		}
	}

	return false
}

// probeOnce sends a query to the proxy through a socket inside its own
// netns and reports whether it answered in time. It is a no-op (true)
// when no proxy is bound.
func (d *buildDNS) probeOnce() bool {
	d.mu.Lock()
	dialer, p := d.dialer, d.proxy
	d.mu.Unlock()

	if p == nil || dialer == nil {
		return true
	}

	c, err := dialer.DialUDP(d.cfg.ListenAddr, 0)
	if err == nil {
		defer c.Close() //nolint:errcheck // probe socket

		m := new(dns.Msg)
		m.SetQuestion(probeName, dns.TypeA)

		_ = c.SetDeadline(time.Now().Add(probeTimeout))

		co := &dns.Conn{Conn: c}
		if err = co.WriteMsg(m); err == nil {
			var r *dns.Msg

			if r, err = co.ReadMsg(); err == nil && r.Id != m.Id {
				err = errBuildDNSProcGone
			}
		}
	}

	if err == nil {
		return true
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.proxy != p {
		return true // rebound meanwhile
	}

	d.log.Error("buildkit dns proxy: liveness probe through the buildkitd netns failed; redirect cleared first (DNS fails open to the upstream), rebinding",
		"error", err)
	d.unbindLocked("liveness probe failed") // clears the redirect before stopping

	return false
}

// admitProject applies the per-project in-flight cap (see
// maxInflightPerProject).
func (d *buildDNS) admitProject(project string) (release func(), ok bool) {
	if project == "" {
		// Unbound / unattributed steps are audit: one of them must not be
		// able to REFUSE the others (that would fail closed). They rely on
		// the per-cgroup and global limits.
		return func() {}, true
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.projInflight[project] >= maxInflightPerProject {
		return nil, false
	}

	d.projInflight[project]++

	return func() {
		d.mu.Lock()
		if d.projInflight[project]--; d.projInflight[project] <= 0 {
			delete(d.projInflight, project)
		}
		d.mu.Unlock()
	}, true
}
