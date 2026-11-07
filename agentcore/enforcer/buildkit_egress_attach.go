// Package enforcer — BuildKit egress attach.
//
// When buildkitd runs rootful + privileged in K8s (the upstream-blessed
// shape for runc + per-RUN process sandbox), runc creates RUN-step
// cgroups at the cgroup root (e.g. /sys/fs/cgroup/buildkit/<runc-id>/)
// rather than nested under the buildkitd pod's cgroup. The agent's
// normal per-pod eBPF attach therefore misses RUN-step egress entirely
// because cgroup_skb inheritance only flows downward from the attach
// point.
//
// BuildKitEgressAttach loads its own EBPFHandle and attaches the same
// egress filter program at the configured BuildKit cgroup parents. The
// existing SessionRegistry + CgroupJoiner pipeline supplies per-RUN
// attribution via LookupBuildKitBinding so events from these cgroups
// inherit session_ref + vertex_digest + per-row CI overrides.
//
// Datapath. When the platform can load the egress_bk object
// (BuildKitPlatform) the attach uses the per-RUN-cgroup policy slot
// table: a BuildPolicyBinder ties each RUN cgroup to a project policy
// slot and a mode (audit | shadow | enforce); cgroups it cannot tie to
// exactly one project's policy run in audit. Without a policy source,
// every cgroup is audit and the behaviour is the original observation +
// attribution. A platform without BuildKitPlatform falls back to the
// per-pod object in always-audit mode.

package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BuildKitEgressAttach owns the manager-side eBPF attach for BuildKit
// RUN-step cgroup parents. One instance is created per agent process;
// Close releases the eBPF program, all attached cgroup links, and the
// ringbuf reader.
type BuildKitEgressAttach struct {
	handle   EBPFHandle // legacy always-audit path (nil with the slot datapath)
	dp       BuildKitDatapath
	binder   *BuildPolicyBinder
	registry *SessionRegistry
	links    []CgroupLink
	recorder *ViolationRecorder

	unhook func()

	// dnsSvc is the build DNS proxy (nil when not enabled or not
	// startable).
	dnsSvc *buildDNS

	cancel   context.CancelFunc
	stopRing func()

	flusherDone chan struct{}

	// ancestors are the subtree-root cgroup ids this attach registered
	// with the sock_attr LSM filter; released on Close.
	ancestors []uint64
	registrar SockAncestorRegistrar

	// sessions resolves the build sessions that may have been open at a
	// given time (including recently closed or dropped ones) and whether
	// that answer is reliable; used by the flusher for the
	// session-level attribution fallback.
	sessions SessionsLookup

	// bindings resolves a cgroup's final binding at flush time.
	bindings BindingLookup

	// joinWindow is the hold window; heldRows are unbound rows carried
	// to the next flush (touched only by the flusher goroutine).
	joinWindow time.Duration
	heldRows   []Violation

	closeOnce sync.Once
}

// SessionsLookup returns the build sessions that may have owned egress
// at a given time, and false when that set cannot be trusted (history
// watcher disconnected around that time), in which case no session
// fallback is applied.
type SessionsLookup func(at time.Time) ([]SessionState, bool)

// BuildKitAttachOption tunes StartBuildKitEgressAttach.
type BuildKitAttachOption func(*buildKitAttachConfig)

type buildKitAttachConfig struct {
	sessions SessionsLookup
	bindings BindingLookup

	joinWindow time.Duration
	// holdWindow is the pre-bind SYN hold window (0 disables the hold).
	holdWindow time.Duration

	policySrc  BuildPolicySource
	dnsProxy   *BuildDNSConfig
	registry   *SessionRegistry
	trusted    []net.IPNet
	runLevel   int // >0 fixes the RUN-cgroup level (tests only)
	dns        []net.IP
	dnsSkipped []string
}

// WithBuildPolicySource supplies per-project policies to the slot
// datapath. Without it every build cgroup runs in audit.
func WithBuildPolicySource(src BuildPolicySource) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.policySrc = src }
}

// WithBuildKitRegistry gives the attach the session registry so its
// policy binder can observe cgroup bindings, sessions and history
// reliability. Required for binding; without it all cgroups stay audit.
func WithBuildKitRegistry(r *SessionRegistry) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.registry = r }
}

// WithBuildKitTrustedCIDRs sets the trusted networks of the slot
// datapath (traffic to them is allowed without rules). Default none, so
// every build connection is observed.
func WithBuildKitTrustedCIDRs(n []net.IPNet) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.trusted = n }
}

// WithBuildKitDNSUpstreams sets the DNS upstream address(es) the port-53
// pin allows for build cgroups in shadow/enforce (host:port or bare IPv4;
// only the address is used). Port 53 to anything else is denied there, so
// without it (an empty list) the pin is off. Required for enforce until
// the build DNS proxy exists: it does not rely on trusted networks.
//
// The upstream must be the resolver buildkitd's RUN steps actually use
// (buildkitd's resolv.conf or its [dns] setting); otherwise every build's
// DNS is flagged or dropped as a bypass. The pin is evaluated before the
// rules, so an explicit deny rule on the upstream IP:53 is overridden.
// Hostnames cannot be pinned and are skipped with a warning.
func WithBuildKitDNSUpstreams(upstreams []string) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) {
		for _, u := range upstreams {
			host := strings.TrimSpace(u)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			if ip := net.ParseIP(host).To4(); ip != nil {
				c.dns = append(c.dns, ip)
			} else {
				c.dnsSkipped = append(c.dnsSkipped, u)
			}
		}
	}
}

// WithBuildKitRunLevel fixes the RUN cgroup level instead of finding it
// in the kernel from the parent cgroup ids. For tests only.
func WithBuildKitRunLevel(level int) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.runLevel = level }
}

// WithBindingLookup overrides the flush-time cgroup binding resolver.
// The default is the hook installed with SetBuildKitEventLookup, falling
// back to the live lookup.
func WithBindingLookup(fn BindingLookup) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.bindings = fn }
}

// WithSessionLookup overrides the session resolver used for the
// session-level attribution fallback. The default is the hook installed
// with SetBuildKitSessionLookup.
func WithSessionLookup(fn SessionsLookup) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.sessions = fn }
}

// StartBuildKitEgressAttach loads an EBPFHandle, attaches it at every
// path in paths, and starts a ringbuf reader that routes events from
// the watched cgroups into a shared recorder; events from cgroups with
// no BuildKit binding are flagged build_unattributed. When
// bucketInterval > 0 and report is non-nil, a flusher goroutine sends
// accumulated violations to report on each tick.
//
// If paths is empty, returns (nil, nil) — the caller has opted out at
// the cgroup level and no attach is performed.
func StartBuildKitEgressAttach(
	parent context.Context,
	platform Platform,
	paths []string,
	log *slog.Logger,
	report ReportFunc,
	bucketInterval time.Duration,
	opts ...BuildKitAttachOption,
) (*BuildKitEgressAttach, error) {
	if len(paths) == 0 {
		return nil, nil //nolint:nilnil // documented: no paths == opt-out, not error
	}

	cfg := buildKitAttachConfig{sessions: lookupBuildKitSessions, bindings: lookupBuildKitEventBinding, joinWindow: joinPendingWindow, holdWindow: DefaultSynHoldWindow}
	for _, o := range opts {
		o(&cfg)
	}

	if bkp, ok := platform.(BuildKitPlatform); ok {
		return startBuildKitSlotAttach(parent, bkp, platform, paths, log, report, bucketInterval, &cfg)
	}

	// Legacy: the per-pod object, always audit (observation + attribution).
	handle, err := platform.LoadEBPF(true, nil)
	if err != nil {
		return nil, fmt.Errorf("load buildkit ebpf: %w", err)
	}

	links := make([]CgroupLink, 0, len(paths))

	for _, p := range paths {
		link, attachErr := handle.AttachCgroup(p)
		if attachErr != nil {
			for _, l := range links {
				_ = l.Close()
			}

			_ = handle.Close()

			return nil, fmt.Errorf("attach buildkit cgroup %q: %w", p, attachErr)
		}

		links = append(links, link)

		log.Info("buildkit egress attach: cgroup attached", "path", p)
	}

	// Register each attach path as a monitored subtree root so the LSM
	// hooks give every socket created beneath it (any RUN cgroup, at
	// any nesting depth, from its first connect) an owner. Without
	// this the egress program has no sk_storage owner for RUN cgroups
	// and emits no event at all.
	var (
		registrar SockAncestorRegistrar
		ancestors []uint64
	)

	if rg, ok := handle.(SockAncestorRegistrar); ok {
		registrar = rg

		for _, p := range paths {
			id, idErr := platform.CgroupID(p)
			if idErr == nil {
				idErr = rg.AddSockKnownAncestor(id)
			}

			if idErr != nil {
				for _, a := range ancestors {
					rg.RemoveSockKnownAncestor(a)
				}

				for _, l := range links {
					_ = l.Close()
				}

				_ = handle.Close()

				return nil, fmt.Errorf("register buildkit cgroup %q for socket capture: %w", p, idErr)
			}

			ancestors = append(ancestors, id)
		}
	} else {
		log.Warn("buildkit egress attach: handle cannot register cgroup subtrees; RUN-step egress will not be observed")
	}

	recorder := NewViolationRecorder(nil)
	if bucketInterval > 0 {
		recorder.SetBucketMode()
	}

	ctx, cancel := context.WithCancel(parent) //nolint:gosec // cancel stored on b, called in Close

	// Audit mode is a live cell. The cgroup_skb program reads it on every
	// event to decide drop-vs-audit. We never flip it back to enforce
	// mode in this code path (the buildkit attach is observation-only).
	auditMode := &atomic.Bool{}
	auditMode.Store(true)

	stopRing, err := handle.StartRingbufReader(
		ctx,
		func(_ uint64) *ViolationRecorder {
			// Every event from the watched subtree is recorded. Events
			// from cgroups the cgroup-join layer has not bound to a
			// session+vertex are flagged build_unattributed when the
			// bucket flushes, rather than dropped: an unbound RUN
			// cgroup is exactly where a mis-join or a join race would
			// hide egress.
			return recorder
		},
		auditMode,
	)
	if err != nil {
		cancel()

		for _, l := range links {
			_ = l.Close()
		}

		_ = handle.Close()

		return nil, fmt.Errorf("start buildkit ringbuf reader: %w", err)
	}

	b := &BuildKitEgressAttach{
		handle:      handle,
		links:       links,
		recorder:    recorder,
		cancel:      cancel,
		stopRing:    stopRing,
		flusherDone: make(chan struct{}),
		ancestors:   ancestors,
		registrar:   registrar,
		sessions:    cfg.sessions,
		bindings:    cfg.bindings,
		joinWindow:  cfg.joinWindow,
	}

	if bucketInterval > 0 && report != nil {
		go b.runFlusher(ctx, bucketInterval, report, log)
	} else {
		close(b.flusherDone)
	}

	return b, nil
}

// runFlusher drains the recorder on each tick and submits a Report. The
// ContainerInfo passed to report carries no project_path — per-row
// BuildProjectPath / BuildJobID stamped by the egress handler is what
// the server uses for routing (see splitReportForBuildKit on the EE
// side).
func (b *BuildKitEgressAttach) runFlusher(
	ctx context.Context,
	interval time.Duration,
	report ReportFunc,
	log *slog.Logger,
) {
	defer close(b.flusherDone)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	info := ContainerInfo{
		ContainerID: "buildkit-egress-attach",
		StartedAt:   time.Now(),
	}

	flush := func(bucketTS time.Time, final bool) {
		violations, dns, overflow := b.collect(final, interval)

		if b.dnsSvc != nil {
			dns = append(dns, b.dnsSvc.DrainDNS()...)
		}

		if len(violations) == 0 && len(dns) == 0 {
			return
		}

		attributeBySession(violations, b.sessions)
		markUnattributed(violations)

		if b.binder != nil {
			b.binder.Annotate(violations)
		}

		if b.dnsSvc != nil {
			b.dnsSvc.StampDomains(violations)
		}

		if b.dp != nil {
			FinalizeUnbound(violations)
		}

		stats := &EgressStats{
			DNSActivity:   dns,
			Violations:    violations,
			OverflowCount: overflow,
		}

		report(context.Background(), info, stats, true, bucketTS)

		log.Debug("buildkit egress attach: bucket flushed",
			"violations", len(violations),
			"dns_entries", len(dns),
			"overflow", overflow,
		)
	}

	for {
		select {
		case <-ctx.Done():
			// Final flush so a partial bucket is not lost on
			// restart or shutdown.
			flush(time.Now(), true)

			return
		case bucketTS := <-ticker.C:
			flush(bucketTS, false)
		}
	}
}

// markUnattributed flags violations that carry no BuildKit binding
// (neither a session/vertex nor an ambiguous candidate set).
func markUnattributed(violations []Violation) {
	for i := range violations {
		v := &violations[i]
		if v.BuildSessionRef == "" && !v.BuildAmbiguous && v.BuildProjectPath == "" {
			v.BuildUnattributed = true
		}
	}
}

// Close releases the cgroup links, stops the ringbuf reader, and frees
// the eBPF handle. Safe to call multiple times.
func (b *BuildKitEgressAttach) Close() error {
	var firstErr error

	b.closeOnce.Do(func() {
		// Stop the ringbuf reader first: stopRing owns its own derived
		// context (it does not depend on ours) and returns only once the
		// reader goroutine has exited, so every event it already pulled is
		// in the recorder. Only then cancel the flusher's context, whose
		// final flush therefore sees those late events.
		b.stopRing()
		b.cancel()
		<-b.flusherDone

		if b.dnsSvc != nil {
			b.dnsSvc.Close()
		}

		if b.unhook != nil {
			b.unhook()
		}

		if b.binder != nil {
			b.binder.Close()
		}

		if b.registrar != nil {
			for _, id := range b.ancestors {
				b.registrar.RemoveSockKnownAncestor(id)
			}
		}

		for _, l := range b.links {
			if err := l.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		if b.handle != nil {
			if err := b.handle.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		if b.dp != nil {
			if err := b.dp.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})

	return firstErr
}

// collect drains the recorder for a flush and resolves the rows.
//
// Rows recorded before the cgroup-join layer linked their RUN cgroup
// carry no binding; they are resolved here with the final binding. Rows
// whose join may still be pending are held for the next flush (never on
// the final one, and only when the interval is long enough that each row
// is held at most once). Held rows live in a slice on the attach, not
// the recorder, so they bypass the recorder's per-bucket cap; they are
// older than the interval at the next flush, hence never held twice.
func (b *BuildKitEgressAttach) collect(final bool, interval time.Duration) ([]Violation, []DNSActivityEntry, int64) {
	violations, dns, overflow := b.recorder.SnapshotAndReset()

	violations = append(b.heldRows, violations...)
	b.heldRows = nil

	violations, b.heldRows = resolveAtFlush(violations, b.bindings, time.Now(),
		!final && interval > 2*b.joinWindow, b.joinWindow)

	return violations, dns, overflow
}

// joinPendingWindow is the default for how long after an event its RUN
// cgroup may still be waiting for the join layer: the joiner retries a
// match for its deferred-match timeout (2s by default) from cgroup
// creation, plus margin. A row younger than this that is still unbound
// at flush may yet be linked, so it is held for the next flush. Use
// JoinPendingWindowFor to derive it from a non-default timeout.
const joinPendingWindow = 3 * time.Second

// DefaultSynHoldWindow is the default pre-bind SYN hold window: the
// joiner's deferred-match deadline.
const DefaultSynHoldWindow = 2 * time.Second

// WithBuildKitSynHoldWindow sets how long a RUN cgroup without a policy
// entry has its TCP SYNs held (dropped so the kernel retransmit lands
// after binding) while an enforce policy is in play. Zero disables the
// hold. Default DefaultSynHoldWindow.
func WithBuildKitSynHoldWindow(d time.Duration) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.holdWindow = d }
}

// JoinPendingWindowFor derives the hold window from the joiner's
// deferred-match timeout (the WithDeferredMatch value) plus one second of
// margin.
func JoinPendingWindowFor(deferredMatchTimeout time.Duration) time.Duration {
	return deferredMatchTimeout + time.Second
}

// WithJoinPendingWindow sets the hold window; pass
// JoinPendingWindowFor(timeout) when the joiner is built with a
// non-default WithDeferredMatch. Default 3s.
func WithJoinPendingWindow(d time.Duration) BuildKitAttachOption {
	return func(c *buildKitAttachConfig) { c.joinWindow = d }
}

// resolveAtFlush re-resolves rows that were unbound when recorded. A row
// is "unbound" when it carries no session, project or ambiguity of its
// own and has a cgroup id. For those, the binding that exists NOW (live,
// or retained after the cgroup was removed) is authoritative: it is the
// join layer's final decision, exact or deliberately ambiguous, and is
// applied unchanged, so nothing here can turn an ambiguous join into a
// single attribution. Rows still unbound and younger than
// joinPendingWindow are returned as held when canHold is set; everything
// else proceeds to the session fallback / unattributed flagging.
func resolveAtFlush(
	violations []Violation, lookup BindingLookup, now time.Time, canHold bool, window time.Duration,
) ([]Violation, []Violation) {
	if lookup == nil {
		return violations, nil
	}

	out := violations[:0]

	var held []Violation

	for _, v := range violations {
		if v.CgroupID == 0 || v.BuildSessionRef != "" || v.BuildProjectPath != "" || v.BuildAmbiguous {
			out = append(out, v)

			continue
		}

		if binding, ok := lookup(v.CgroupID, v.Timestamp); ok {
			applyBuildKitBinding(&v, binding)
			out = append(out, v)

			continue
		}

		if canHold && now.Sub(v.Timestamp) < window {
			held = append(held, v)

			continue
		}

		out = append(out, v)
	}

	return out, held
}

// attributeBySession is the session-level fallback for rows the
// cgroup-join layer could not bind to a vertex. A BuildKit RUN step of
// unknown vertex still belongs to some open build session, and the
// session carries the CI identity (LEITWACHT_CI_* build-args). When the
// sessions open at the event time resolve to a single CI identity the
// row inherits it (session_ref is stamped only when exactly one session
// is open; vertex stays empty). When several sessions with different
// identities overlap, nothing is guessed: the row records the candidate
// sessions as ambiguous and, carrying no project, lands in the
// unattributed bucket.
func attributeBySession(violations []Violation, sessions SessionsLookup) {
	if sessions == nil {
		return
	}

	for i := range violations {
		v := &violations[i]
		if v.BuildSessionRef != "" || v.BuildProjectPath != "" {
			continue
		}

		if v.BuildAmbiguous && !candidatesShareSession(v.BuildAmbiguousCandidates) {
			continue
		}

		cands, reliable := sessions(v.Timestamp)
		if !reliable {
			// The history watcher was down around this event, so the
			// session set may be missing the real owner. Do not guess.
			continue
		}

		open := activeSessionsAt(cands, v.Timestamp)

		if v.BuildAmbiguous && len(v.BuildAmbiguousCandidates) > 0 {
			// Narrow to the one session every candidate belongs to.
			ref := v.BuildAmbiguousCandidates[0].SessionRef
			open = filterSession(open, ref)
		}

		switch len(open) {
		case 0:
			continue
		case 1:
			s := open[0]

			// A project without a job id is not routable (the server
			// requires both) and must not borrow another job's id:
			// leave the row unattributed.
			if p, j, _, _, _, _, _ := CIOverrideFromFrontendAttrs(s.FrontendAttrs); p == "" || j == "" {
				continue
			}

			v.BuildSessionRef = s.Ref
			v.BuildAmbiguous = false
			v.BuildAmbiguousCandidates = nil
			v.BuildProjectPath, v.BuildJobID, v.BuildPipelineID,
				v.BuildJobName, v.BuildJobStage, v.BuildGitRef,
				v.BuildJobURL = CIOverrideFromFrontendAttrs(s.FrontendAttrs)

			continue
		}

		if identity, ok := commonCIIdentity(open); ok {
			v.BuildProjectPath, v.BuildJobID, v.BuildPipelineID,
				v.BuildJobName, v.BuildJobStage, v.BuildGitRef,
				v.BuildJobURL = CIOverrideFromFrontendAttrs(identity)

			continue
		}

		v.BuildAmbiguous = true

		v.BuildAmbiguousCandidates = v.BuildAmbiguousCandidates[:0]
		for _, s := range open {
			v.BuildAmbiguousCandidates = append(v.BuildAmbiguousCandidates,
				AmbiguousCandidate{SessionRef: s.Ref})
		}
	}
}

func candidatesShareSession(cs []AmbiguousCandidate) bool {
	if len(cs) == 0 {
		return false
	}

	for _, c := range cs[1:] {
		if c.SessionRef != cs[0].SessionRef {
			return false
		}
	}

	return true
}

func filterSession(in []SessionState, ref string) []SessionState {
	var out []SessionState

	for _, s := range in {
		if s.Ref == ref {
			out = append(out, s)
		}
	}

	return out
}

// sessionGrace tolerates clock skew between buildkitd's session
// timestamps and the agent's event time, and the tail of a session that
// completed just before a late-flushed event.
const sessionGrace = 5 * time.Second

func activeSessionsAt(all []SessionState, at time.Time) []SessionState {
	var out []SessionState

	for _, s := range all {
		if !s.StartedAt.IsZero() && at.Before(s.StartedAt.Add(-sessionGrace)) {
			continue
		}

		if s.Completed && at.After(s.CompletedAt.Add(sessionGrace)) {
			continue
		}

		out = append(out, s)
	}

	return out
}

// commonCIIdentity reports the FrontendAttrs of the open sessions when
// they all carry the same non-empty CI project+job.
func commonCIIdentity(open []SessionState) (map[string]string, bool) {
	project, job, _, _, _, _, _ := CIOverrideFromFrontendAttrs(open[0].FrontendAttrs)
	if project == "" || job == "" {
		return nil, false
	}

	for _, s := range open[1:] {
		p, j, _, _, _, _, _ := CIOverrideFromFrontendAttrs(s.FrontendAttrs)
		if p != project || j != job {
			return nil, false
		}
	}

	return open[0].FrontendAttrs, true
}

// startBuildKitSlotAttach is the egress_bk path of StartBuildKitEgressAttach.
func startBuildKitSlotAttach(
	parent context.Context,
	bkp BuildKitPlatform,
	platform Platform,
	paths []string,
	log *slog.Logger,
	report ReportFunc,
	bucketInterval time.Duration,
	cfg *buildKitAttachConfig,
) (*BuildKitEgressAttach, error) {
	dp, err := bkp.LoadBuildKitEBPF(cfg.trusted)
	if err != nil {
		return nil, fmt.Errorf("load buildkit ebpf: %w", err)
	}

	cleanup := func(links []CgroupLink) {
		for _, l := range links {
			_ = l.Close()
		}

		_ = dp.Close()
	}

	parentIDs := make([]uint64, 0, len(paths))

	for _, p := range paths {
		id, idErr := platform.CgroupID(p)
		if idErr != nil {
			cleanup(nil)

			return nil, fmt.Errorf("resolve buildkit cgroup %q: %w", p, idErr)
		}

		parentIDs = append(parentIDs, id)
	}

	if len(cfg.dnsSkipped) > 0 {
		log.Warn("buildkit egress attach: DNS upstream is not an IPv4 address and was skipped; the port-53 pin may be off",
			"skipped", strings.Join(cfg.dnsSkipped, ","))
	}

	if len(cfg.dns) == 0 {
		log.Warn("buildkit egress attach: no DNS upstream configured; the port-53 pin is off")
	}

	if cfg.runLevel < 0 || cfg.runLevel > 64 {
		cleanup(nil)

		return nil, fmt.Errorf("%w: %d", errBKConfigRange, cfg.runLevel)
	}

	err = dp.SetConfig(BKConfig{ParentIDs: parentIDs, DNSUpstreams: cfg.dns, RunLevel: uint32(cfg.runLevel), HoldWindow: cfg.holdWindow}) //nolint:gosec // range-checked above
	if err != nil {
		cleanup(nil)

		return nil, fmt.Errorf("set buildkit config: %w", err)
	}

	links := make([]CgroupLink, 0, len(paths))

	for _, p := range paths {
		link, attachErr := dp.AttachCgroup(p)
		if attachErr != nil {
			cleanup(links)

			return nil, fmt.Errorf("attach buildkit cgroup %q: %w", p, attachErr)
		}

		links = append(links, link)

		log.Info("buildkit egress attach: cgroup attached", "path", p)
	}

	var (
		registrar SockAncestorRegistrar
		ancestors []uint64
	)

	if rg, ok := dp.(SockAncestorRegistrar); ok {
		registrar = rg

		for i, p := range paths {
			id := parentIDs[i]

			idErr := rg.AddSockKnownAncestor(id)
			if idErr != nil {
				for _, a := range ancestors {
					rg.RemoveSockKnownAncestor(a)
				}

				cleanup(links)

				return nil, fmt.Errorf("register buildkit cgroup %q for socket capture: %w", p, idErr)
			}

			ancestors = append(ancestors, id)
		}
	} else {
		log.Warn("buildkit egress attach: handle cannot register cgroup subtrees; RUN-step egress will not be observed")
	}

	recorder := NewViolationRecorder(nil)
	if bucketInterval > 0 {
		recorder.SetBucketMode()
	}

	ctx, cancel := context.WithCancel(parent) //nolint:gosec // cancel stored on b, called in Close

	b := &BuildKitEgressAttach{
		dp:          dp,
		registry:    cfg.registry,
		links:       links,
		recorder:    recorder,
		cancel:      cancel,
		flusherDone: make(chan struct{}),
		ancestors:   ancestors,
		registrar:   registrar,
		sessions:    cfg.sessions,
		bindings:    cfg.bindings,
		joinWindow:  cfg.joinWindow,
	}

	if cfg.registry != nil {
		opts := []BinderOption{
			WithBinderTrustedCIDRs(cfg.trusted),
			WithBinderHistory(cfg.registry.HistoryDisconnected, cfg.sessions),
			WithBinderCgroupCheck(cfg.registry.bindingFor, defaultStatFn),
			WithBinderDNSUpstreams(cfg.dns),
		}

		b.binder = NewBuildPolicyBinder(cfg.policySrc, dp, log, opts...)
		b.unhook = b.binder.InstallEventHook()

		// Seed from bindings that already exist (a resolver swap installs
		// a new attach under live RUN cgroups), then observe changes.
		for id, binding := range cfg.registry.CgroupSnapshot() {
			b.binder.OnBind(id, binding)
		}

		cfg.registry.SetBindingObserver(b.binder)

		prev := b.unhook
		binder := b.binder
		reg := cfg.registry

		b.unhook = func() {
			reg.ClearBindingObserver(binder)
			prev()
		}

		b.binder.RefreshHold()

		go b.binder.Run(ctx)

		if cfg.dnsProxy != nil {
			svc, dnsErr := startBuildDNS(ctx, *cfg.dnsProxy, log, platform, dp, b.binder, recorder,
				parentIDs, paths, cfg.dns)
			if dnsErr != nil {
				// A misconfigured proxy must not take the attach (and
				// with it all build egress observation) down.
				log.Error("buildkit dns proxy not started; domain rules are not enforced for build steps", "error", dnsErr)
			}

			b.dnsSvc = svc
		}
	} else if cfg.dnsProxy != nil {
		log.Warn("buildkit dns proxy not started: no session registry; domain rules are not enforced for build steps")
	}

	stopRing, err := dp.StartRingbufReader(ctx, func(_ uint64) *ViolationRecorder { return recorder })
	if err != nil {
		cancel()

		if b.dnsSvc != nil {
			b.dnsSvc.Close()
		}

		if b.unhook != nil {
			b.unhook()
		}

		if b.binder != nil {
			b.binder.Close()
		}

		if registrar != nil {
			for _, a := range ancestors {
				registrar.RemoveSockKnownAncestor(a)
			}
		}

		cleanup(links)

		return nil, fmt.Errorf("start buildkit ringbuf reader: %w", err)
	}

	b.stopRing = stopRing

	if bucketInterval > 0 && report != nil {
		go b.runFlusher(ctx, bucketInterval, report, log)
	} else {
		close(b.flusherDone)
	}

	return b, nil
}
