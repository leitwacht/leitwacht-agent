package enforcer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestStartBuildKitEgressAttach_OptOut covers the opt-out path —
// callers pass an empty path slice when the operator sets
// BuildkitDisableCgroupAttach=true. No EBPF load, no attach, no
// ringbuf reader, no error.
func TestStartBuildKitEgressAttach_OptOut(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, nil, log, nil, 0)
	if err != nil {
		t.Fatalf("opt-out returned err=%v, want nil", err)
	}

	if attach != nil {
		t.Errorf("opt-out returned non-nil attach=%v, want nil", attach)
	}

	if plat.ebpfLoaded {
		t.Error("opt-out loaded EBPF; expected no load")
	}
}

// TestStartBuildKitEgressAttach_AttachesAtEachPath verifies the
// happy path: one EBPFHandle loaded, one AttachCgroup per configured
// path, ringbuf reader started. Close releases everything.
func TestStartBuildKitEgressAttach_AttachesAtEachPath(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	paths := []string{"/sys/fs/cgroup/buildkit", "/sys/fs/cgroup/init"}

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, paths, log, nil, 0)
	if err != nil {
		t.Fatalf("StartBuildKitEgressAttach: %v", err)
	}

	if attach == nil {
		t.Fatal("nil attach on happy path")
	}

	t.Cleanup(func() {
		if closeErr := attach.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	if !plat.ebpfLoaded {
		t.Error("EBPF not loaded")
	}

	handle := attach.handle.(*fakeEBPFHandle)
	if handle.attachCount != len(paths) {
		t.Errorf("attachCount=%d, want %d", handle.attachCount, len(paths))
	}

	if !plat.ringbufStarted {
		t.Error("ringbuf reader not started")
	}
}

// TestStartBuildKitEgressAttach_LoadFails: when LoadEBPF errors, no
// links remain attached and the returned error wraps the cause.
func TestStartBuildKitEgressAttach_LoadFails(t *testing.T) {
	t.Parallel()

	loadErr := errors.New("kernel too old")
	plat := &fakePlatform{loadEBPFErr: loadErr}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
	)
	if attach != nil {
		t.Errorf("attach=%v on load failure, want nil", attach)
	}

	if err == nil {
		t.Fatal("nil err on load failure")
	}

	if !errors.Is(err, loadErr) {
		t.Errorf("err=%v, want it to wrap %v", err, loadErr)
	}
}

// TestStartBuildKitEgressAttach_AttachFailsCleansUp: when a later
// AttachCgroup fails, the earlier links from the same call are closed
// and the EBPFHandle is released. Without this, a partial-attach
// failure would leak BPF program references.
func TestStartBuildKitEgressAttach_AttachFailsCleansUp(t *testing.T) {
	t.Parallel()

	attachErr := errors.New("permission denied")
	plat := &fakePlatform{attachCgroupErr: attachErr}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
	)
	if attach != nil {
		t.Errorf("attach=%v on attach failure, want nil", attach)
	}

	if err == nil {
		t.Fatal("nil err on attach failure")
	}

	if !errors.Is(err, attachErr) {
		t.Errorf("err=%v, want it to wrap %v", err, attachErr)
	}

	if !plat.ebpfClosed {
		t.Error("EBPFHandle not closed after attach failure; would leak BPF program")
	}
}

// TestMarkUnattributed verifies the flush-time marker: violations with
// no BuildKit binding are flagged build_unattributed instead of being
// dropped; bound and ambiguous ones are left alone.
func TestMarkUnattributed(t *testing.T) {
	t.Parallel()

	vs := []Violation{
		{IP: "192.0.2.1"},
		{IP: "192.0.2.2", BuildSessionRef: "sess-1"},
		{IP: "192.0.2.3", BuildAmbiguous: true},
	}

	markUnattributed(vs)

	if !vs[0].BuildUnattributed {
		t.Error("unbound violation not marked unattributed")
	}

	if vs[1].BuildUnattributed || vs[2].BuildUnattributed {
		t.Error("bound/ambiguous violation wrongly marked unattributed")
	}
}

// TestBuildKitEgressAttach_FlusherEmitsReports verifies the bucket
// flusher invokes ReportFunc with the recorder's accumulated stats.
// Drives one tick, asserts a report arrives carrying the violations.
func TestBuildKitEgressAttach_FlusherEmitsReports(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	reports := make(chan *EgressStats, 1)
	report := func(_ context.Context, _ ContainerInfo, stats *EgressStats, _ bool, _ time.Time) {
		reports <- stats
	}

	// Tight interval to keep the test fast.
	const tick = 20 * time.Millisecond

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat,
		[]string{"/sys/fs/cgroup/buildkit"},
		log, report, tick,
	)
	if err != nil {
		t.Fatalf("StartBuildKitEgressAttach: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	// Seed the shared recorder. The flusher should drain this on the
	// next tick and pass it to ReportFunc.
	attach.recorder.RecordViolation(Violation{
		IP:        "1.2.3.4",
		Port:      443,
		Action:    "audit",
		Timestamp: time.Now(),
	})

	select {
	case stats := <-reports:
		if len(stats.Violations) != 1 {
			t.Errorf("flush emitted %d violations, want 1", len(stats.Violations))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flusher did not emit a report within 2s")
	}
}

// TestBuildKitEgressAttach_CloseStopsRingBeforeCancel pins the shutdown
// order: the ringbuf reader must be stopped before the flusher's context
// is cancelled, so the flusher's final flush sees every late event.
func TestBuildKitEgressAttach_CloseStopsRingBeforeCancel(t *testing.T) {
	t.Parallel()

	var order []string

	done := make(chan struct{})
	close(done)

	b := &BuildKitEgressAttach{
		handle:      &fakeEBPFHandle{platform: &fakePlatform{}},
		cancel:      func() { order = append(order, "cancel") },
		stopRing:    func() { order = append(order, "stopRing") },
		flusherDone: done,
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if len(order) != 2 || order[0] != "stopRing" || order[1] != "cancel" {
		t.Fatalf("shutdown order = %v, want [stopRing cancel]", order)
	}
}

// TestBuildKitEgressAttach_RegistersSubtreeRoot is the regression test
// for "BuildKit RUN egress never produces a row": the LSM gate only
// creates socket owners for monitored cgroups, so the attach must
// register each BuildKit parent as a subtree root (covering every RUN
// cgroup beneath it from its first connect) and release it on Close.
func TestBuildKitEgressAttach_RegistersSubtreeRoot(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit", "/sys/fs/cgroup/init"}, log, nil, 0,
	)
	if err != nil {
		t.Fatalf("StartBuildKitEgressAttach: %v", err)
	}

	handle := attach.handle.(*fakeEBPFHandle)

	if n := handle.ancestorCount(); n != 2 {
		t.Fatalf("registered %d subtree roots, want 2", n)
	}

	if err := attach.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if n := handle.ancestorCount(); n != 0 {
		t.Errorf("Close left %d subtree roots registered, want 0", n)
	}
}

// connectedRegistry returns a registry whose history watcher has
// connected, so events after this point are not in the pre-connect gap.
func connectedRegistry() *SessionRegistry {
	r := NewSessionRegistry(time.Second)
	r.SetHistoryConnected(true)

	return r
}

func okSessions(ss []SessionState) SessionsLookup {
	return func(time.Time) ([]SessionState, bool) { return ss, true }
}

func sess(ref, project, job string, start time.Time) SessionState {
	return SessionState{
		Ref:       ref,
		StartedAt: start,
		FrontendAttrs: map[string]string{
			FrontendAttrKeyProjectPath: project,
			FrontendAttrKeyJobID:       job,
		},
	}
}

func TestAttributeBySession(t *testing.T) {
	t.Parallel()

	now := time.Now()
	one := []SessionState{sess("s1", "grp/proj", "42", now.Add(-time.Minute))}

	t.Run("single open session stamps CI identity", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, okSessions(one))

		if vs[0].BuildSessionRef != "s1" || vs[0].BuildProjectPath != "grp/proj" || vs[0].BuildJobID != "42" {
			t.Errorf("not session-attributed: %+v", vs[0])
		}

		if vs[0].BuildVertexDigest != "" {
			t.Error("vertex stamped on a session-level row")
		}

		markUnattributed(vs)

		if vs[0].BuildUnattributed {
			t.Error("session-attributed row flagged unattributed")
		}
	})

	t.Run("ambiguous candidates in one session narrow to it", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{
			IP: "1.1.1.1", Timestamp: now, BuildAmbiguous: true,
			BuildAmbiguousCandidates: []AmbiguousCandidate{{SessionRef: "s1", VertexDigest: "a"}, {SessionRef: "s1", VertexDigest: "b"}},
		}}
		two := append([]SessionState{sess("s2", "other/p", "7", now)}, one...)
		attributeBySession(vs, okSessions(two))

		if vs[0].BuildSessionRef != "s1" || vs[0].BuildAmbiguous {
			t.Errorf("want session s1 attribution, got %+v", vs[0])
		}
	})

	t.Run("overlapping sessions with different identities stay unattributed", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		two := append([]SessionState{sess("s2", "other/p", "7", now)}, one...)
		attributeBySession(vs, okSessions(two))

		if vs[0].BuildProjectPath != "" || vs[0].BuildSessionRef != "" {
			t.Errorf("guessed an identity: %+v", vs[0])
		}

		if !vs[0].BuildAmbiguous || len(vs[0].BuildAmbiguousCandidates) != 2 {
			t.Errorf("want ambiguous over both sessions, got %+v", vs[0])
		}
	})

	t.Run("overlapping sessions of one job share identity", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		two := append([]SessionState{sess("s2", "grp/proj", "42", now)}, one...)
		attributeBySession(vs, okSessions(two))

		if vs[0].BuildProjectPath != "grp/proj" || vs[0].BuildSessionRef != "" {
			t.Errorf("want project-level attribution without session, got %+v", vs[0])
		}
	})

	t.Run("completed long ago and not yet started are ignored", func(t *testing.T) {
		t.Parallel()

		done := sess("old", "grp/old", "1", now.Add(-time.Hour))
		done.Completed, done.CompletedAt = true, now.Add(-30*time.Minute)

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, okSessions([]SessionState{done, sess("future", "grp/f", "2", now.Add(time.Hour))}))

		if vs[0].BuildSessionRef != "" {
			t.Errorf("attributed to an inactive session: %+v", vs[0])
		}
	})
}

// TestBuildKitEgressAttach_FlusherSessionFallback drives the flusher
// end to end: an unbound row picks up the lone open session's identity.
func TestBuildKitEgressAttach_FlusherSessionFallback(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reports := make(chan *EgressStats, 1)
	report := func(_ context.Context, _ ContainerInfo, stats *EgressStats, _ bool, _ time.Time) {
		reports <- stats
	}

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, report, 20*time.Millisecond,
		WithSessionLookup(okSessions([]SessionState{sess("s1", "grp/proj", "42", time.Now().Add(-time.Minute))})),
	)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	attach.recorder.RecordViolation(Violation{IP: "1.2.3.4", Port: 80, Action: "audit", Timestamp: time.Now()})

	select {
	case stats := <-reports:
		if len(stats.Violations) != 1 || stats.Violations[0].BuildProjectPath != "grp/proj" {
			t.Errorf("flushed row not session-attributed: %+v", stats.Violations)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report")
	}
}

func TestAttributeBySession_Unroutable(t *testing.T) {
	t.Parallel()

	now := time.Now()
	noJob := sess("s1", "grp/proj", "", now.Add(-time.Minute))

	vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
	attributeBySession(vs, okSessions([]SessionState{noJob}))

	if vs[0].BuildProjectPath != "" || vs[0].BuildSessionRef != "" {
		t.Errorf("project without job id was attributed: %+v", vs[0])
	}

	markUnattributed(vs)

	if !vs[0].BuildUnattributed {
		t.Error("unroutable row not flagged unattributed")
	}
}

func TestProjectLevelRowNotFlaggedUnattributed(t *testing.T) {
	t.Parallel()

	now := time.Now()
	two := []SessionState{sess("a", "grp/proj", "42", now), sess("b", "grp/proj", "42", now)}

	vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
	attributeBySession(vs, okSessions(two))
	markUnattributed(vs)

	if vs[0].BuildProjectPath != "grp/proj" || vs[0].BuildUnattributed {
		t.Errorf("contradictory flags: %+v", vs[0])
	}
}

// Registry-backed fallback safety: a flush that runs after the owning
// session left the registry must still see it as a candidate.
func TestSessionFallback_RegistryTombstones(t *testing.T) {
	t.Parallel()

	now := time.Now().Add(time.Second) // events after the registry's first connect

	victim := func(r *SessionRegistry) {
		r.RegisterSession("victim", now.Add(-time.Minute), map[string]string{
			FrontendAttrKeyProjectPath: "team/victim", FrontendAttrKeyJobID: "1",
		})
	}
	attacker := func(r *SessionRegistry) {
		r.RegisterSession("attacker", now.Add(-time.Minute), map[string]string{
			FrontendAttrKeyProjectPath: "team/attacker", FrontendAttrKeyJobID: "2",
		})
	}

	run := func(r *SessionRegistry) Violation {
		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, r.SessionsActiveAt)
		markUnattributed(vs)

		return vs[0]
	}

	t.Run("session swept before flush is still a candidate", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		victim(r)
		attacker(r)
		r.CompleteSession("attacker", now.Add(2*time.Second)) // finished just after the event
		r.Sweep(now.Add(time.Minute))                         // flush runs after the TTL

		v := run(r)
		if v.BuildProjectPath != "" || !v.BuildAmbiguous {
			t.Errorf("swept session ignored, victim single-attributed: %+v", v)
		}
	})

	t.Run("DELETED history event does not shrink the candidate set", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		victim(r)
		attacker(r)
		r.DropSession("attacker")

		v := run(r)
		if v.BuildProjectPath == "team/victim" || !v.BuildAmbiguous {
			t.Errorf("attacker's step attributed to victim: %+v", v)
		}
	})

	t.Run("history disconnected refuses the fallback", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		victim(r)
		r.SetHistoryConnected(false)

		v := run(r)
		if v.BuildSessionRef != "" || v.BuildProjectPath != "" || !v.BuildUnattributed {
			t.Errorf("attributed while history was down: %+v", v)
		}
	})

	t.Run("reconnected gap still covers events inside it", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		victim(r)
		r.SetHistoryConnected(false)
		r.SetHistoryConnected(true)

		if _, ok := r.SessionsActiveAt(time.Now()); ok {
			t.Error("event inside a past disconnect gap reported reliable")
		}

		if _, ok := r.SessionsActiveAt(time.Now().Add(time.Minute)); !ok {
			t.Error("event long after the gap reported unreliable")
		}
	})

	t.Run("single live session still attributes", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		victim(r)

		v := run(r)
		if v.BuildProjectPath != "team/victim" || v.BuildUnattributed {
			t.Errorf("lone session not attributed: %+v", v)
		}
	})
}

func TestSessionFallback_ReliabilityGaps(t *testing.T) {
	t.Parallel()

	t.Run("event before first watcher connect is unreliable", func(t *testing.T) {
		t.Parallel()

		r := NewSessionRegistry(time.Second)
		if _, ok := r.SessionsActiveAt(time.Now()); ok {
			t.Error("reliable with the watcher never connected")
		}

		r.SetHistoryConnected(true)

		if _, ok := r.SessionsActiveAt(time.Now().Add(-time.Minute)); ok {
			t.Error("event before first connect reported reliable")
		}

		if _, ok := r.SessionsActiveAt(time.Now().Add(time.Millisecond)); !ok {
			t.Error("event after first connect reported unreliable")
		}
	})

	t.Run("tombstone cap eviction marks older events unreliable", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		base := time.Now()

		for i := 0; i <= maxTombstones; i++ {
			ref := "s" + string(rune('a'+i%26)) + time.Duration(i).String()
			r.RegisterSession(ref, base, nil)
			r.DropSession(ref)
		}

		if _, ok := r.SessionsActiveAt(base); ok {
			t.Error("event at the time of an evicted tombstone reported reliable")
		}

		if _, ok := r.SessionsActiveAt(time.Now().Add(time.Minute)); !ok {
			t.Error("event after the evicted window reported unreliable")
		}
	})

	t.Run("gap-list overflow marks the dropped gap unreliable", func(t *testing.T) {
		t.Parallel()

		r := connectedRegistry()
		early := time.Now()

		for i := 0; i < maxGaps+2; i++ {
			r.SetHistoryConnected(false)
			time.Sleep(2 * time.Millisecond)
			r.SetHistoryConnected(true)
			time.Sleep(2 * time.Millisecond)
		}

		// The list is capped, but the dropped gaps must still poison
		// their window (the grace around surviving gaps would mask it
		// in a timing check, so assert the bookkeeping directly).
		r.mu.RLock()
		lost, n := r.lostUntil, len(r.gaps)
		r.mu.RUnlock()

		if n != maxGaps || !lost.After(early) {
			t.Errorf("gaps=%d lostUntil=%v: overflow not tracked", n, lost)
		}

		if _, ok := r.SessionsActiveAt(time.Now().Add(time.Minute)); !ok {
			t.Error("event long after all gaps reported unreliable")
		}
	})
}
