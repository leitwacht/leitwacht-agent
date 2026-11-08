package enforcer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
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

func sessAttrs(ref, project, job, pipeline string, start time.Time) SessionState {
	s := sess(ref, project, job, start)
	if pipeline != "" {
		s.FrontendAttrs[FrontendAttrKeyPipelineID] = pipeline
	}

	return s
}

func TestAttributeBySessionProjectLift(t *testing.T) {
	t.Parallel()

	now := time.Now()
	st := now.Add(-time.Minute)

	noJob := sess("s3", "grp/p", "", st)
	noProj := sess("s3", "", "9", st)

	var many []SessionState

	for i := range 20 {
		many = append(many, sess(fmt.Sprintf("m%02d", i), "grp/p", fmt.Sprintf("%03d", 99-i), st))
	}

	many = append(many, sess("long", "grp/p", strings.Repeat("9", 300), st))

	cases := []struct {
		name         string
		sessions     []SessionState
		wantProject  string
		wantPipeline string
		wantJobs     []string
	}{
		{"same project different jobs", []SessionState{sess("a", "grp/p", "20", st), sess("b", "grp/p", "10", st)}, "grp/p", "", []string{"10", "20"}},
		{"same pipeline", []SessionState{sessAttrs("a", "grp/p", "1", "P7", st), sessAttrs("b", "grp/p", "2", "P7", st)}, "grp/p", "P7", []string{"1", "2"}},
		{"different pipelines", []SessionState{sessAttrs("a", "grp/p", "1", "P7", st), sessAttrs("b", "grp/p", "2", "P8", st)}, "grp/p", "", []string{"1", "2"}},
		{"different projects", []SessionState{sess("a", "grp/p", "1", st), sess("b", "grp/q", "2", st)}, "", "", nil},
		{"one missing job", []SessionState{sess("a", "grp/p", "1", st), noJob}, "", "", nil},
		{"one missing project", []SessionState{sess("a", "grp/p", "1", st), noProj}, "", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
			attributeBySession(vs, okSessions(tc.sessions))

			v := vs[0]
			if !v.BuildAmbiguous || len(v.BuildAmbiguousCandidates) != len(tc.sessions) {
				t.Fatalf("want ambiguous over all sessions, got %+v", v)
			}

			if v.BuildProjectPath != tc.wantProject || v.BuildPipelineID != tc.wantPipeline ||
				!slices.Equal(v.BuildAmbiguousJobIDs, tc.wantJobs) {
				t.Errorf("got project=%q pipeline=%q jobs=%v", v.BuildProjectPath, v.BuildPipelineID, v.BuildAmbiguousJobIDs)
			}

			assertNoJobLevel(t, v)
		})
	}

	t.Run("cap keeps the 16 smallest ids, order independent", func(t *testing.T) {
		t.Parallel()

		want := []string{
			"080", "081", "082", "083", "084", "085", "086", "087",
			"088", "089", "090", "091", "092", "093", "094", "095",
		}

		for seed := range 5 {
			in := slices.Clone(many[:20])
			rand.New(rand.NewPCG(uint64(seed), 1)).Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })

			vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
			attributeBySession(vs, okSessions(in))

			if !slices.Equal(vs[0].BuildAmbiguousJobIDs, want) {
				t.Fatalf("seed %d: got %v", seed, vs[0].BuildAmbiguousJobIDs)
			}

			assertNoJobLevel(t, vs[0])
		}
	})

	longID := strings.Repeat("9", 129)

	t.Run("over-long job id dropped", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, okSessions([]SessionState{
			sess("a", "grp/p", longID, st), sess("b", "grp/p", "1", st),
		}))

		if got := vs[0].BuildAmbiguousJobIDs; !slices.Equal(got, []string{"1"}) || vs[0].BuildProjectPath != "grp/p" {
			t.Errorf("got %+v", vs[0])
		}

		assertNoJobLevel(t, vs[0])
	})

	t.Run("all job ids over-long no lift", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, okSessions([]SessionState{
			sess("a", "grp/p", longID, st), sess("b", "grp/p", longID+"1", st),
		}))

		if vs[0].BuildProjectPath != "" || vs[0].BuildAmbiguousJobIDs != nil || !vs[0].BuildAmbiguous {
			t.Errorf("got %+v", vs[0])
		}
	})

	t.Run("over-long project no lift", func(t *testing.T) {
		t.Parallel()

		lp := strings.Repeat("p", 129)
		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, okSessions([]SessionState{sess("a", lp, "1", st), sess("b", lp, "2", st)}))

		if vs[0].BuildProjectPath != "" || vs[0].BuildAmbiguousJobIDs != nil || !vs[0].BuildAmbiguous {
			t.Errorf("got %+v", vs[0])
		}
	})

	t.Run("over-long pipeline lifts without pipeline", func(t *testing.T) {
		t.Parallel()

		lp := strings.Repeat("q", 129)
		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, okSessions([]SessionState{
			sessAttrs("a", "grp/p", "1", lp, st), sessAttrs("b", "grp/p", "2", lp, st),
		}))

		if vs[0].BuildProjectPath != "grp/p" || vs[0].BuildPipelineID != "" || len(vs[0].BuildAmbiguousJobIDs) != 2 {
			t.Errorf("got %+v", vs[0])
		}
	})

	t.Run("unreliable sessions unchanged", func(t *testing.T) {
		t.Parallel()

		vs := []Violation{{IP: "1.1.1.1", Timestamp: now}}
		attributeBySession(vs, func(time.Time) ([]SessionState, bool) {
			return []SessionState{sess("a", "grp/p", "1", st), sess("b", "grp/p", "2", st)}, false
		})

		if vs[0].BuildAmbiguous || vs[0].BuildProjectPath != "" {
			t.Errorf("changed on unreliable: %+v", vs[0])
		}
	})

	joinRow := func() []Violation {
		return []Violation{{
			IP: "1.1.1.1", Timestamp: now, BuildAmbiguous: true, BindingStrength: StrengthAmbiguous,
			BuildAmbiguousCandidates: []AmbiguousCandidate{
				{SessionRef: "a", VertexDigest: "x"}, {SessionRef: "b", VertexDigest: "y"},
			},
		}}
	}

	t.Run("join ambiguous multi-session lifted", func(t *testing.T) {
		t.Parallel()

		vs := joinRow()
		// An unrelated open session must not influence the lift.
		attributeBySession(vs, okSessions([]SessionState{
			sess("a", "grp/p", "2", st), sess("b", "grp/p", "1", st), sess("z", "other/q", "5", st),
		}))

		v := vs[0]
		if v.BuildProjectPath != "grp/p" || !slices.Equal(v.BuildAmbiguousJobIDs, []string{"1", "2"}) ||
			!v.BuildAmbiguous || len(v.BuildAmbiguousCandidates) != 2 ||
			v.BuildAmbiguousCandidates[0].VertexDigest != "x" {
			t.Errorf("got %+v", v)
		}

		assertNoJobLevel(t, v)
	})

	t.Run("join ambiguous candidate session missing", func(t *testing.T) {
		t.Parallel()

		vs := joinRow()
		attributeBySession(vs, okSessions([]SessionState{sess("a", "grp/p", "2", st)}))

		if vs[0].BuildProjectPath != "" || vs[0].BuildAmbiguousJobIDs != nil {
			t.Errorf("lifted with unknown session: %+v", vs[0])
		}
	})

	t.Run("join ambiguous unreliable", func(t *testing.T) {
		t.Parallel()

		vs := joinRow()
		attributeBySession(vs, func(time.Time) ([]SessionState, bool) {
			return []SessionState{sess("a", "grp/p", "2", st), sess("b", "grp/p", "1", st)}, false
		})

		if vs[0].BuildProjectPath != "" {
			t.Errorf("lifted on unreliable: %+v", vs[0])
		}
	})
}

func assertNoJobLevel(t *testing.T, v Violation) {
	t.Helper()

	if v.BuildSessionRef != "" || v.BuildJobID != "" || v.BuildJobName != "" ||
		v.BuildJobStage != "" || v.BuildGitRef != "" || v.BuildJobURL != "" {
		t.Errorf("job-level field set on lifted row: %+v", v)
	}
}

func TestAttributeBySessionJoinNegatives(t *testing.T) {
	t.Parallel()

	now := time.Now()
	st := now.Add(-time.Minute)

	row := func(refs ...string) []Violation {
		v := Violation{IP: "1.1.1.1", Timestamp: now, BuildAmbiguous: true, BindingStrength: StrengthAmbiguous}
		for _, r := range refs {
			v.BuildAmbiguousCandidates = append(v.BuildAmbiguousCandidates, AmbiguousCandidate{SessionRef: r})
		}

		return []Violation{v}
	}

	t.Run("different projects", func(t *testing.T) {
		t.Parallel()

		vs := row("a", "b")
		attributeBySession(vs, okSessions([]SessionState{sess("a", "g/p", "1", st), sess("b", "g/q", "2", st)}))

		if vs[0].BuildProjectPath != "" || vs[0].BuildAmbiguousJobIDs != nil {
			t.Errorf("got %+v", vs[0])
		}
	})

	t.Run("candidate without job id", func(t *testing.T) {
		t.Parallel()

		vs := row("a", "b")
		attributeBySession(vs, okSessions([]SessionState{sess("a", "g/p", "1", st), sess("b", "g/p", "", st)}))

		if vs[0].BuildProjectPath != "" {
			t.Errorf("got %+v", vs[0])
		}
	})

	t.Run("duplicate session refs still lift over distinct sessions", func(t *testing.T) {
		t.Parallel()

		vs := row("a", "b", "a")
		attributeBySession(vs, okSessions([]SessionState{sess("a", "g/p", "1", st), sess("b", "g/p", "2", st)}))

		if vs[0].BuildProjectPath != "g/p" || !slices.Equal(vs[0].BuildAmbiguousJobIDs, []string{"1", "2"}) {
			t.Errorf("got %+v", vs[0])
		}
	})
}

func TestAttributeBySessionUntrustedCandidates(t *testing.T) {
	t.Parallel()

	now := time.Now()
	st := now.Add(-time.Minute)

	for _, strength := range []string{StrengthSessionLevel, StrengthWeakTail} {
		row := func() []Violation {
			return []Violation{{
				IP: "1.1.1.1", Timestamp: now, BuildAmbiguous: true, BindingStrength: strength,
				BuildAmbiguousCandidates: []AmbiguousCandidate{{SessionRef: "a", VertexDigest: "x"}},
			}}
		}

		t.Run(strength+" owner absent from candidates, other project", func(t *testing.T) {
			t.Parallel()

			vs := row()
			attributeBySession(vs, okSessions([]SessionState{sess("a", "g/p", "1", st), sess("owner", "g/q", "2", st)}))

			v := vs[0]
			if v.BuildProjectPath != "" || v.BuildSessionRef != "" || v.BuildJobID != "" || !v.BuildAmbiguous || len(v.BuildAmbiguousCandidates) != 2 {
				t.Errorf("trusted the candidate set: %+v", v)
			}
		})

		t.Run(strength+" owner absent from candidates, same project", func(t *testing.T) {
			t.Parallel()

			vs := row()
			attributeBySession(vs, okSessions([]SessionState{sess("a", "g/p", "1", st), sess("owner", "g/p", "2", st)}))

			v := vs[0]
			if v.BuildProjectPath != "g/p" || !slices.Equal(v.BuildAmbiguousJobIDs, []string{"1", "2"}) || !v.BuildAmbiguous {
				t.Errorf("got %+v", v)
			}

			assertNoJobLevel(t, v)
		})

		t.Run(strength+" single open session owner not in candidates", func(t *testing.T) {
			t.Parallel()

			vs := row()
			attributeBySession(vs, okSessions([]SessionState{sess("shell", "g/q", "9", st)}))

			v := vs[0]
			if v.BuildSessionRef != "shell" || v.BuildProjectPath != "g/q" || v.BuildJobID != "9" || v.BuildAmbiguous || v.BuildAmbiguousCandidates != nil {
				t.Errorf("want single-session attribution, got %+v", v)
			}
		})

		t.Run(strength+" unreliable unchanged", func(t *testing.T) {
			t.Parallel()

			vs := row()
			attributeBySession(vs, func(time.Time) ([]SessionState, bool) {
				return []SessionState{sess("shell", "g/q", "9", st)}, false
			})

			if vs[0].BuildSessionRef != "" || vs[0].BuildProjectPath != "" {
				t.Errorf("got %+v", vs[0])
			}
		})
	}
}
