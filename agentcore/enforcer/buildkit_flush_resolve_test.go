package enforcer

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func bindingFor(session, digest, project, job string) CgroupBinding {
	return CgroupBinding{
		SessionRef: session, VertexDigest: digest, VertexName: "RUN " + digest,
		FrontendAttrs: map[string]string{
			FrontendAttrKeyProjectPath: project, FrontendAttrKeyJobID: job,
		},
	}
}

// The failing case from the field: wget connects milliseconds after the
// RUN cgroup appears, before the join links it, so the row is recorded
// unbound. At flush the final binding must be applied.
func TestResolveAtFlush_EventBeforeLinkGetsVertex(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	now := time.Now()

	rows := []Violation{{IP: "93.184.216.34", CgroupID: 42, Timestamp: now.Add(-20 * time.Second)}}

	// Linked only after the event was recorded.
	r.LinkCgroup(42, bindingFor("sA", "dig1", "grp/a", "7"))

	out, held := resolveAtFlush(rows, r.LookupForEvent, now, true, joinPendingWindow)
	if len(held) != 0 || len(out) != 1 {
		t.Fatalf("out=%d held=%d", len(out), len(held))
	}

	if v := out[0]; v.BuildSessionRef != "sA" || v.BuildVertexDigest != "dig1" || v.BuildProjectPath != "grp/a" || v.BuildJobID != "7" {
		t.Errorf("late link not applied: %+v", v)
	}
}

// A short RUN step can finish, and its cgroup be removed, before the
// flush. Its final binding is retained and still resolves events from
// while it existed, but never as a live binding and not for later events
// (cgroup ids are inodes and can be recycled).
func TestResolveAtFlush_RemovedCgroupStillResolves(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	now := time.Now()

	r.LinkCgroup(7, bindingFor("sA", "dig1", "grp/a", "7"))
	r.UnlinkCgroup(7)

	if _, ok := r.LookupByCgroupID(7); ok {
		t.Fatal("removed cgroup still live")
	}

	out, _ := resolveAtFlush([]Violation{{CgroupID: 7, Timestamp: now.Add(-time.Second)}}, r.LookupForEvent, now.Add(time.Minute), false, joinPendingWindow)
	if out[0].BuildVertexDigest != "dig1" {
		t.Errorf("retired binding not applied: %+v", out[0])
	}

	// An event after the removal belongs to a different (id-reusing)
	// cgroup and must not resolve to the retired binding.
	out, _ = resolveAtFlush([]Violation{{CgroupID: 7, Timestamp: time.Now().Add(5 * time.Second)}}, r.LookupForEvent, now.Add(time.Minute), false, joinPendingWindow)
	if out[0].BuildSessionRef != "" {
		t.Errorf("id reuse resolved to a retired binding: %+v", out[0])
	}

	// A fresh live link for the same id supersedes the retired entry.
	r.LinkCgroup(7, bindingFor("sB", "dig2", "grp/b", "8"))

	out, _ = resolveAtFlush([]Violation{{CgroupID: 7, Timestamp: time.Now()}}, r.LookupForEvent, now, false, joinPendingWindow)
	if out[0].BuildSessionRef != "sB" {
		t.Errorf("live link did not supersede: %+v", out[0])
	}
}

func TestResolveAtFlush_UnresolvedHoldAndDeadline(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	now := time.Now()

	young := Violation{IP: "1.1.1.1", CgroupID: 9, Timestamp: now.Add(-time.Second)}
	old := Violation{IP: "2.2.2.2", CgroupID: 9, Timestamp: now.Add(-joinPendingWindow - time.Second)}

	out, held := resolveAtFlush([]Violation{young, old}, r.LookupForEvent, now, true, joinPendingWindow)
	if len(held) != 1 || held[0].IP != "1.1.1.1" || len(out) != 1 || out[0].IP != "2.2.2.2" {
		t.Fatalf("hold/deadline split wrong: out=%+v held=%+v", out, held)
	}

	// Past the deadline the old row proceeds, and (no session open) is
	// flagged unattributed rather than guessed.
	markUnattributed(out)

	if !out[0].BuildUnattributed {
		t.Error("unresolved-at-deadline row not flagged unattributed")
	}

	// The final flush never holds.
	out, held = resolveAtFlush([]Violation{young}, r.LookupForEvent, now, false, joinPendingWindow)
	if len(held) != 0 || len(out) != 1 {
		t.Errorf("final flush held rows: out=%d held=%d", len(out), len(held))
	}
}

// Overlapping builds: each cgroup resolves to its OWN session and
// vertex via its exact link; nothing is pooled across sessions.
func TestResolveAtFlush_OverlappingSessionsEachOwnVertex(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	now := time.Now()

	r.LinkCgroup(1, bindingFor("sA", "dA", "grp/a", "1"))
	r.LinkCgroup(2, bindingFor("sB", "dB", "grp/b", "2"))

	rows := []Violation{
		{IP: "1.1.1.1", CgroupID: 1, Timestamp: now.Add(-10 * time.Second)},
		{IP: "1.1.1.1", CgroupID: 2, Timestamp: now.Add(-10 * time.Second)},
	}

	out, _ := resolveAtFlush(rows, r.LookupForEvent, now, true, joinPendingWindow)

	if out[0].BuildSessionRef != "sA" || out[0].BuildVertexDigest != "dA" || out[0].BuildProjectPath != "grp/a" {
		t.Errorf("row 1 wrong: %+v", out[0])
	}

	if out[1].BuildSessionRef != "sB" || out[1].BuildVertexDigest != "dB" || out[1].BuildProjectPath != "grp/b" {
		t.Errorf("row 2 wrong: %+v", out[1])
	}
}

// An ambiguous join is applied as ambiguous: the flush never upgrades it
// to a single attribution, and the session fallback leaves it alone.
func TestResolveAtFlush_AmbiguousStaysAmbiguous(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	now := time.Now()

	r.LinkCgroup(3, CgroupBinding{
		Ambiguous: true,
		AmbiguousCandidates: []AmbiguousCandidate{
			{SessionRef: "sA", VertexDigest: "d1"}, {SessionRef: "sB", VertexDigest: "d2"},
		},
	})

	out, _ := resolveAtFlush([]Violation{{CgroupID: 3, Timestamp: now.Add(-10 * time.Second)}}, r.LookupForEvent, now, true, joinPendingWindow)
	if !out[0].BuildAmbiguous || out[0].BuildSessionRef != "" || out[0].BuildProjectPath != "" {
		t.Errorf("ambiguous join was upgraded: %+v", out[0])
	}

	attributeBySession(out, okSessions([]SessionState{sess("sA", "grp/a", "1", now.Add(-time.Minute))}))

	if out[0].BuildSessionRef != "" || out[0].BuildProjectPath != "" {
		t.Errorf("session fallback overrode an ambiguous join: %+v", out[0])
	}
}

// End to end through the flusher: a row recorded unbound is reported with
// the binding that exists at flush time.
func TestBuildKitEgressAttach_FlusherResolvesLateLink(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reports := make(chan *EgressStats, 1)
	report := func(_ context.Context, _ ContainerInfo, stats *EgressStats, _ bool, _ time.Time) {
		select {
		case reports <- stats:
		default:
		}
	}

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, report, 20*time.Millisecond,
		WithBindingLookup(func(id uint64, _ time.Time) (CgroupBinding, bool) {
			if id != 5 {
				return CgroupBinding{}, false
			}

			return bindingFor("sA", "dA", "grp/a", "1"), true
		}),
		WithSessionLookup(okSessions(nil)),
	)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	attach.recorder.RecordViolation(Violation{IP: "1.2.3.4", Port: 80, CgroupID: 5, Action: "audit", Timestamp: time.Now()})

	select {
	case stats := <-reports:
		if len(stats.Violations) != 1 || stats.Violations[0].BuildVertexDigest != "dA" {
			t.Errorf("flush did not apply the late binding: %+v", stats.Violations)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report")
	}
}

// A held row must survive even when the next bucket is already at the
// recorder's cap (held rows bypass the recorder).
func TestCollect_HeldRowSurvivesFullNextBucket(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
		WithBindingLookup(func(uint64, time.Time) (CgroupBinding, bool) { return CgroupBinding{}, false }),
	)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	interval := time.Hour // far above 2x the hold window

	attach.recorder.RecordViolation(Violation{IP: "9.9.9.9", CgroupID: 5, Timestamp: time.Now()})

	out, _, _ := attach.collect(false, interval)
	if len(out) != 0 || len(attach.heldRows) != 1 {
		t.Fatalf("young unresolved row not held: out=%d held=%d", len(out), len(attach.heldRows))
	}

	// A full interval passes: the held row is now old.
	attach.heldRows[0].Timestamp = time.Now().Add(-time.Hour)
	attach.recorder.SetBucketMode()

	// Next bucket fills the recorder to its cap.
	for i := 0; i < maxViolationsPerBucket+10; i++ {
		attach.recorder.RecordViolation(Violation{IP: "8.8.8.8", CgroupID: 6, Timestamp: time.Now().Add(-time.Hour)})
	}

	out, _, overflow := attach.collect(false, interval)

	var found bool

	for _, v := range out {
		if v.IP == "9.9.9.9" {
			found = true
		}
	}

	if !found || overflow == 0 {
		t.Errorf("held row lost behind a full bucket (found=%v overflow=%d)", found, overflow)
	}

	if len(attach.heldRows) != 0 {
		t.Error("held row held twice")
	}
}

// The hold window follows the joiner's deferred-match timeout.
func TestJoinPendingWindowFor(t *testing.T) {
	t.Parallel()

	if got := JoinPendingWindowFor(2 * time.Second); got != joinPendingWindow {
		t.Errorf("default timeout derives %v, want the %v default", got, joinPendingWindow)
	}

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
		WithJoinPendingWindow(JoinPendingWindowFor(10*time.Second)),
		WithBindingLookup(func(uint64, time.Time) (CgroupBinding, bool) { return CgroupBinding{}, false }),
	)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	// A row 5s old is past the 3s default but inside the 11s window: held.
	attach.recorder.RecordViolation(Violation{IP: "1.1.1.1", CgroupID: 5, Timestamp: time.Now().Add(-5 * time.Second)})

	_, _, _ = attach.collect(false, time.Hour)

	if len(attach.heldRows) != 1 {
		t.Errorf("custom window not honoured: held=%d", len(attach.heldRows))
	}
}
