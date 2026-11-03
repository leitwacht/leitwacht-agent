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

	closeOnce sync.Once
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
) (*BuildKitEgressAttach, error) {
	if len(paths) == 0 {
		return nil, nil //nolint:nilnil // documented: no paths == opt-out, not error
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
		if v.BuildSessionRef == "" && !v.BuildAmbiguous {
			v.BuildUnattributed = true
		}
	}
}

// Close releases the cgroup links, stops the ringbuf reader, and frees
// the eBPF handle. Safe to call multiple times.
func (b *BuildKitEgressAttach) Close() error {
	var firstErr error

	b.closeOnce.Do(func() {
		b.cancel()
		b.stopRing()
		<-b.flusherDone

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
