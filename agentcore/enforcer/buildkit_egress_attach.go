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
// Always loads in audit mode: the allow/deny maps are empty so no
// traffic is blocked. The intent is observation + attribution for
// shared build infrastructure where per-CI-job policy is enforced at
// the CI runner pod (via the normal per-container path), not at
// buildkitd. Enforcement of buildkit-specific egress policy is a
// follow-up — first we need to see the traffic.

package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// BuildKitEgressAttach owns the manager-side eBPF attach for BuildKit
// RUN-step cgroup parents. One instance is created per agent process;
// Close releases the eBPF program, all attached cgroup links, and the
// ringbuf reader.
type BuildKitEgressAttach struct {
	handle   EBPFHandle
	links    []CgroupLink
	recorder *ViolationRecorder

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

	cfg := buildKitAttachConfig{sessions: lookupBuildKitSessions}
	for _, o := range opts {
		o(&cfg)
	}

	// Always audit: the buildkit attach is for observation + attribution.
	// CI-job-scoped enforcement runs at the CI runner pod's per-container
	// attach (unchanged from before this code existed).
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

	flush := func(bucketTS time.Time) {
		violations, dns, overflow := b.recorder.SnapshotAndReset()
		if len(violations) == 0 && len(dns) == 0 {
			return
		}

		attributeBySession(violations, b.sessions)
		markUnattributed(violations)

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
			flush(time.Now())

			return
		case bucketTS := <-ticker.C:
			flush(bucketTS)
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

		if err := b.handle.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})

	return firstErr
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
