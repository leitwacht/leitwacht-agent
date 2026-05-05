package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// ErrBuildkitCgroupRequired is returned when BUILDKIT_ENABLED is true but BUILDKIT_CGROUP is empty.
var ErrBuildkitCgroupRequired = errors.New("BUILDKIT_CGROUP is required when BUILDKIT_ENABLED=true")

// BuildKit Egress Monitoring — Security Model
//
// In block mode, buildkit traffic is subject to the same eBPF positive allowlist
// as job container traffic. Only IPs resolved from allowed domains (via the DNS
// proxy) are added to the allow map; everything else is dropped.
//
// Effective against:
//   - Exfiltration to attacker-controlled domains (DNS returns NXDOMAIN)
//   - Direct-IP access (no allow map entry → eBPF drops packet)
//   - DNS tunneling (domain not in allowlist → NXDOMAIN)
//
// NOT effective against (requires content-layer defenses):
//   - Typosquatted/compromised packages served from allowed registries
//     (e.g., malicious module on proxy.golang.org). Network-level monitoring
//     cannot distinguish legitimate from malicious content on the same domain.
//     Mitigate with: lockfiles, go.sum, dependency scanning, binary authorization.
//
// Known observability gaps (not exploitable — attacker code has finished):
//   - Drain window: after drain delay expires, buildkitd infra traffic (layer
//     pushes, cache exports) is unmonitored until the next job attaches.
//   - Layer cache: cached build stages produce zero network traffic on subsequent
//     builds. The first build is fully monitored; repeats are invisible.
//   - DNS proxy bypass: if buildkitd is not configured to resolve through the
//     leitwacht DNS proxy, DNS telemetry is lost. However, the eBPF allow map
//     is also not populated, so buildkit traffic is blocked in block mode
//     (fails closed, not open).

// BuildkitConfig holds the configuration for BuildKit egress monitoring.
type BuildkitConfig struct {
	CgroupPath   string        // explicit cgroup path for buildkitd
	DNSAddr      string        // host address for buildkit DNS proxy (e.g., "10.0.0.42:15353")
	Upstreams    []string      // DNS upstream servers
	DrainDelay   time.Duration // how long to keep recorder active after job ends
	AgentVersion string        // echoed in the attachment-liveness TXT answer
}

// BuildkitMonitor coordinates BuildKit egress monitoring across jobs.
//
// Architecture: buildkitd runs as a long-lived host daemon, but the eBPF program
// is loaded per-job (per NetnsContext). Each job, the monitor attaches buildkitd's
// cgroup to the job's eBPF program so they share the allow map and ring buffer.
// A host-level DNS proxy (optional) runs for the lifetime of the agent; the
// recorder is swapped per-job so DNS queries are attributed to the active job.
//
// On job end, a configurable drain delay keeps the buildkit cgroup attached
// and recorder active to capture tail traffic (layer pushes, cache exports)
// that continues after buildctl returns.
type BuildkitMonitor struct {
	mu sync.Mutex // protects activeJob, link, drainTimer

	cgroupPath string
	cgroupID   uint64 // resolved once at startup, reused per-job
	drainDelay time.Duration

	// Per-job state (set during AttachJob, cleared after drain).
	activeJob  string
	link       CgroupLink // buildkit cgroup → job's eBPF program
	drainTimer *time.Timer

	// recorder is swapped per-job. Between jobs (after drain), it's nil.
	// The ring buffer reader and DNS proxy read this atomically.
	recorder atomic.Pointer[ViolationRecorder]

	// allowMapFunc is the current job's eBPF AddAllowedIP. Swapped per-job
	// so the buildkit DNS proxy adds resolved IPs to the correct allow map.
	allowMapFunc atomic.Pointer[func(net.IP, []int) error]

	// dnsProxy is the host-level DNS proxy that buildkitd resolves through.
	// Runs for the lifetime of the agent. nil if DNS monitoring is not configured.
	dnsProxy *DNSProxy

	// firewallInstalled tracks whether startBuildkitDNS installed host-netns
	// nftables rules to shield a routable proxy bind. Close() uses this to
	// decide whether to tear the rules down. Loopback/unspecified binds skip
	// the install and this stays false.
	firewallInstalled bool

	// platform is retained so Close() can tear down the host-netns firewall
	// installed in InitBuildkitMonitor when the proxy bound on a routable IP.
	platform Platform

	logger *slog.Logger
}

// InitBuildkitMonitor validates config and optionally starts the host-level DNS proxy.
// The buildkit cgroup is validated but NOT attached to eBPF yet — that happens
// per-job in AttachJob when the job's eBPF program is available.
func InitBuildkitMonitor(
	cfg BuildkitConfig,
	platform Platform,
	logger *slog.Logger,
) (*BuildkitMonitor, error) {
	// Verify cgroup exists.
	_, statErr := os.Stat(cfg.CgroupPath)
	if statErr != nil {
		return nil, fmt.Errorf("buildkit cgroup %s: %w", cfg.CgroupPath, statErr)
	}

	cgID, err := platform.CgroupID(cfg.CgroupPath)
	if err != nil {
		return nil, fmt.Errorf("buildkit cgroup id: %w", err)
	}

	bm := &BuildkitMonitor{
		cgroupPath: cfg.CgroupPath,
		cgroupID:   cgID,
		drainDelay: cfg.DrainDelay,
		platform:   platform,
		logger:     logger,
	}

	// Start host-level DNS proxy if configured.
	if cfg.DNSAddr != "" {
		proxy, dnsErr := startBuildkitDNS(cfg.DNSAddr, cfg.Upstreams, bm, logger, cfg.AgentVersion)
		if dnsErr != nil {
			return nil, fmt.Errorf("buildkit dns proxy: %w", dnsErr)
		}

		bm.dnsProxy = proxy

		// Fence the proxy: when bound on a routable IP (not loopback), install
		// host-netns nftables rules that drop off-host queries. Fail-closed —
		// running with an exposed resolver is worse than not running at all
		// (attackers can poison leitwacht's eBPF allow map for allowlisted
		// domains by making their own queries).
		host, _, splitErr := net.SplitHostPort(cfg.DNSAddr)
		if splitErr != nil {
			proxy.Stop()

			return nil, fmt.Errorf("parse buildkit dns addr %q: %w", cfg.DNSAddr, splitErr)
		}

		listenIP := net.ParseIP(host)

		fwErr := platform.SetupBuildkitDNSFirewall(listenIP)
		if fwErr != nil {
			proxy.Stop()

			return nil, fmt.Errorf("install buildkit dns firewall: %w", fwErr)
		}

		bm.firewallInstalled = !isLoopbackOrUnspecified(listenIP)
	}

	logger.Info("buildkit monitor initialized",
		"cgroup", cfg.CgroupPath,
		"cgroup_id", cgID,
		"dns_addr", cfg.DNSAddr,
		"drain_delay", cfg.DrainDelay,
	)

	return bm, nil
}

// CgroupID returns the buildkitd cgroup ID for registration in cgroupRecorders.
func (bm *BuildkitMonitor) CgroupID() uint64 {
	return bm.cgroupID
}

// LookupRecorder returns the current job's recorder, or nil between jobs.
// Safe to call from the eBPF ring buffer reader and DNS proxy goroutines.
func (bm *BuildkitMonitor) LookupRecorder() *ViolationRecorder {
	return bm.recorder.Load()
}

// AttachJob attaches the buildkit cgroup to the job's eBPF program and
// registers the DNS recorder used by the buildkit DNS proxy. If another job
// is active (concurrent > 1), returns false.
//
// dnsRec is the recorder the buildkit DNS proxy writes into via LookupRecorder.
// It must be the job's shared DNS recorder (nctx.sharedDNSRecorder), because
// the bucket reporter reads DNS activity only from that recorder.
//
// Packet drops from the buildkit cgroup are attributed separately: the caller
// must register bm.CgroupID() in nctx.cgroupRecorders pointing at the job's
// per-container packet recorder, so the ring buffer reader routes ebpf drop
// events to the right recorder.
func (bm *BuildkitMonitor) AttachJob(
	containerID string,
	ebpf EBPFHandle,
	dnsRec *ViolationRecorder,
	pol *policy.ResolvedPolicy,
) (bool, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Cancel any pending drain from the previous job.
	if bm.drainTimer != nil {
		bm.drainTimer.Stop()
		bm.drainTimer = nil

		// Drain was pending — clear the old job so the new one can take over.
		bm.activeJob = ""
		bm.recorder.Store(nil)
		bm.allowMapFunc.Store(nil)

		if bm.link != nil {
			_ = bm.link.Close()
			bm.link = nil
		}
	}

	// Concurrent guard: if a different job is already active, skip.
	if bm.activeJob != "" && bm.activeJob != containerID {
		bm.logger.Warn("buildkit monitoring skipped: another job active, attribution ambiguous",
			"active_job", bm.activeJob[:12],
			"new_job", containerID[:12],
		)

		return false, nil
	}

	// Attach buildkit cgroup to this job's eBPF program.
	link, err := ebpf.AttachCgroup(bm.cgroupPath)
	if err != nil {
		return false, fmt.Errorf("attach buildkit cgroup: %w", err)
	}

	bm.activeJob = containerID
	bm.link = link
	bm.recorder.Store(dnsRec)

	addFn := ebpf.AddAllowedIP
	bm.allowMapFunc.Store(&addFn)

	if bm.dnsProxy != nil {
		bm.dnsProxy.UpdatePolicy(pol)
	}

	bm.logger.Info("buildkit monitoring attached to job",
		"container_id", containerID[:12],
	)

	return true, nil
}

// DetachJob begins draining buildkit traffic for the ending job. The cgroup
// link and recorder stay active for drainDelay to capture tail traffic from
// buildkitd, then are cleared.
func (bm *BuildkitMonitor) DetachJob(containerID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.activeJob != containerID {
		return
	}

	if bm.drainDelay > 0 {
		// Keep cgroup link and recorder active during drain to capture tail traffic.
		bm.drainTimer = time.AfterFunc(bm.drainDelay, func() {
			bm.mu.Lock()
			defer bm.mu.Unlock()

			// Only clear if no new job attached during the drain.
			if bm.activeJob == containerID {
				bm.clearJobLocked()

				bm.logger.Debug("buildkit drain complete",
					"container_id", containerID[:12],
				)
			}
		})

		bm.logger.Info("buildkit monitoring draining",
			"container_id", containerID[:12],
			"drain_delay", bm.drainDelay,
		)
	} else {
		bm.clearJobLocked()

		bm.logger.Info("buildkit monitoring detached",
			"container_id", containerID[:12],
		)
	}
}

// clearJobLocked resets all per-job state. Must be called with bm.mu held.
func (bm *BuildkitMonitor) clearJobLocked() {
	bm.activeJob = ""
	bm.recorder.Store(nil)
	bm.allowMapFunc.Store(nil)

	if bm.link != nil {
		_ = bm.link.Close()
		bm.link = nil
	}

	if bm.dnsProxy != nil {
		bm.dnsProxy.UpdatePolicy(auditAllPolicy())
	}
}

// addToAllowMap delegates to the current job's eBPF AddAllowedIP.
// Returns nil (no-op) between jobs.
func (bm *BuildkitMonitor) addToAllowMap(ip net.IP, ports []int) error {
	fn := bm.allowMapFunc.Load()
	if fn == nil {
		return nil
	}

	return (*fn)(ip, ports)
}

// Close tears down the BuildKit monitor: stops DNS proxy, closes any active link.
func (bm *BuildkitMonitor) Close() {
	bm.mu.Lock()
	if bm.drainTimer != nil {
		bm.drainTimer.Stop()
	}

	if bm.link != nil {
		_ = bm.link.Close()
		bm.link = nil
	}
	bm.mu.Unlock()

	if bm.dnsProxy != nil {
		bm.dnsProxy.Stop()
	}

	if bm.firewallInstalled && bm.platform != nil {
		rmErr := bm.platform.RemoveBuildkitDNSFirewall()
		if rmErr != nil {
			bm.logger.Warn("remove buildkit dns firewall", "error", rmErr)
		}
	}

	bm.logger.Info("buildkit monitor closed")
}

// startBuildkitDNS creates and starts a standalone DNS proxy on a host address
// for buildkitd to resolve through. Unlike the per-container DNS proxy, this
// binds on the host network (no netns tricks) and uses a swappable recorder
// via bm.LookupRecorder.
func startBuildkitDNS(addr string, upstreams []string, bm *BuildkitMonitor, logger *slog.Logger, agentVersion string) (*DNSProxy, error) {
	lc := net.ListenConfig{}

	udpConn, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("bind udp %s: %w", addr, err)
	}

	tcpListener, err := lc.Listen(context.Background(), "tcp4", addr)
	if err != nil {
		if udpConn != nil {
			_ = udpConn.Close()
		}

		return nil, fmt.Errorf("bind tcp %s: %w", addr, err)
	}

	proxyCfg := &DNSProxyConfig{
		Policy:         auditAllPolicy(),
		Upstreams:      upstreams,
		Logger:         logger,
		LookupRecorder: func(_ uint64) *ViolationRecorder { return bm.LookupRecorder() },
		AddToAllowMap:  bm.addToAllowMap,
		AgentVersion:   agentVersion,
	}

	proxy := NewDNSProxy(proxyCfg)
	proxy.Start(udpConn, tcpListener)

	logger.Info("buildkit dns proxy started", "addr", addr)

	return proxy, nil
}

// auditAllPolicy returns a policy that records everything, blocks nothing.
func auditAllPolicy() *policy.ResolvedPolicy {
	return &policy.ResolvedPolicy{
		Action:   policyActionAudit,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": nil},
	}
}
