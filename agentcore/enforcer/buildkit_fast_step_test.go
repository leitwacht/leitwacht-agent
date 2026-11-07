package enforcer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fastStepCmd = "/bin/sh\x00-c\x00wget -q -O /dev/null http://example.net/ && echo two > /two\x00"

func startFastStepJoiner(t *testing.T, root string, reg *SessionRegistry, id uint64) *fakeEventSource {
	t.Helper()

	source := newFakeEventSource()
	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(func(string) (uint64, error) { return id, nil }),
		WithDeferredMatch(600*time.Millisecond, 10*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() { _ = j.Run(ctx) }()

	return source
}

func registerFastStep(reg *SessionRegistry, completedAt time.Time) {
	registerFastStepIn(reg, "sess-fast", "dig-fast", completedAt)
}

func registerFastStepIn(reg *SessionRegistry, session, digest string, completedAt time.Time) {
	reg.RegisterSession(session, time.Now().Add(-time.Minute), nil)
	reg.UpsertVertex(session, VertexState{
		Digest:      digest,
		Name:        "[two 2/2] RUN wget -q -O /dev/null http://example.net/ && echo two > /two",
		StartedAt:   time.Now().Add(-time.Second),
		Completed:   true,
		CompletedAt: completedAt,
	})
}

// A fast RUN step can already be reported completed by the time the
// join reads its cgroup. It must still link (it was running when the
// cgroup appeared); matching only still-open vertices missed it.
func TestCgroupJoiner_FastStepAlreadyCompletedStillLinks(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)
	registerFastStep(reg, time.Now().Add(time.Second))

	cg := stageCgroup(t, root, "ctr-fast", 5151, fastStepCmd)
	source := startFastStepJoiner(t, root, reg, 4242)

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-fast", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4242)

		return ok && b.SessionRef == "sess-fast" && b.VertexDigest == "dig-fast" && !b.Ambiguous
	})
}

// The step finishes (cgroup removed) before BuildKit announces the
// vertex. The argv captured while the process lived is matched after the
// removal, and the binding is retired (resolvable for events from while
// the cgroup existed), never left live.
func TestCgroupJoiner_RemovedBeforeVertexAnnouncedLinksRetired(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)

	cg := stageCgroup(t, root, "ctr-gone", 5252, fastStepCmd)
	source := startFastStepJoiner(t, root, reg, 4343)

	eventAt := time.Now()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-gone", CgroupPath: cg}
	time.Sleep(60 * time.Millisecond) // first attempts: argv captured, no vertex yet

	// The process exits and runc removes the cgroup.
	_ = os.RemoveAll(cg)
	source.removes <- CgroupRemoveEvent{ContainerID: "ctr-gone", CgroupPath: cg}
	time.Sleep(60 * time.Millisecond)

	registerFastStep(reg, time.Now().Add(time.Second))

	waitFor(t, time.Second, func() bool {
		b, ok := reg.LookupForEvent(4343, eventAt)

		return ok && b.VertexDigest == "dig-fast"
	})

	if _, live := reg.LookupByCgroupID(4343); live {
		t.Error("binding for a removed cgroup left live")
	}
}

// A cgroup removed before any argv could be read can never be matched.
func TestCgroupJoiner_RemovedWithoutArgvStaysUnlinked(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)
	registerFastStep(reg, time.Now())

	cg := filepath.Join(root, "cgroups", "ctr-empty")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), nil, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	source := startFastStepJoiner(t, root, reg, 4444)

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-empty", CgroupPath: cg}
	time.Sleep(40 * time.Millisecond)
	source.removes <- CgroupRemoveEvent{ContainerID: "ctr-empty", CgroupPath: cg}
	time.Sleep(200 * time.Millisecond)

	if _, ok := reg.LookupForEvent(4444, time.Now()); ok {
		t.Error("cgroup with no captured argv got a binding")
	}
}

// Completed vertices only count when their interval covers the cgroup's
// appearance: a long-finished vertex with the same text must not match.
func TestCandidateVertices_CompletedMustOverlap(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(time.Minute)
	now := time.Now()

	reg.RegisterSession("s", now.Add(-time.Hour), nil)
	reg.UpsertVertex("s", VertexState{
		Digest: "old", Name: "RUN x", StartedAt: now.Add(-time.Hour),
		Completed: true, CompletedAt: now.Add(-50 * time.Minute),
	})
	reg.UpsertVertex("s", VertexState{
		Digest: "cur", Name: "RUN y", StartedAt: now.Add(-time.Second),
		Completed: true, CompletedAt: now.Add(time.Second),
	})

	got := reg.CandidateVertices(now)
	if len(got) != 1 || got[0].VertexDigest != "cur" {
		t.Fatalf("candidates = %+v, want only the overlapping completed vertex", got)
	}
}

// Session A owns the cgroup but its vertex is not announced yet; session
// B's vertex with the same argv completed just before the cgroup
// appeared. B must not become the sole candidate and win a single link.
func TestCgroupJoiner_CompletedOtherSessionNeverSingleLinks(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)

	reg.RegisterSession("sess-A", time.Now().Add(-time.Minute), nil) // no vertex yet
	registerFastStepIn(reg, "sess-B", "dig-B", time.Now().Add(500*time.Millisecond))

	cg := stageCgroup(t, root, "ctr-ab", 5353, fastStepCmd)
	source := startFastStepJoiner(t, root, reg, 4545)

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-ab", CgroupPath: cg}
	time.Sleep(900 * time.Millisecond) // past the join deadline

	if b, ok := reg.LookupByCgroupID(4545); ok {
		t.Fatalf("cgroup single-linked from a completed vertex of another session: %+v", b)
	}
}

// A completed vertex plus a live vertex with the same argv is an
// ambiguous result, never a single link.
func TestCgroupJoiner_CompletedPlusLiveIsAmbiguous(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)

	registerFastStepIn(reg, "sess-B", "dig-B", time.Now().Add(500*time.Millisecond))

	reg.RegisterSession("sess-A", time.Now().Add(-time.Minute), nil)
	reg.UpsertVertex("sess-A", VertexState{
		Digest: "dig-A", Name: "[two 2/2] RUN wget -q -O /dev/null http://example.net/ && echo two > /two",
		StartedAt: time.Now().Add(-time.Second),
	})

	cg := stageCgroup(t, root, "ctr-mix", 5454, fastStepCmd)
	source := startFastStepJoiner(t, root, reg, 4646)

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-mix", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4646)

		return ok && b.Ambiguous && len(b.AmbiguousCandidates) == 2 && b.SessionRef == ""
	})
}

// A completed vertex that already has a cgroup cannot own a second one,
// even when it is the only session known (A's history not yet seen).
func TestCgroupJoiner_CompletedVertexWithCgroupNeverLinksSecond(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)
	registerFastStep(reg, time.Now().Add(500*time.Millisecond))

	reg.LinkCgroup(1111, CgroupBinding{
		SessionRef: "sess-fast", VertexDigest: "dig-fast", ContainerID: "ctr-first", CgroupPath: "/x",
	})

	cg := stageCgroup(t, root, "ctr-second", 5555, fastStepCmd)
	source := startFastStepJoiner(t, root, reg, 4747)

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-second", CgroupPath: cg}
	time.Sleep(900 * time.Millisecond)

	if _, ok := reg.LookupByCgroupID(4747); ok {
		t.Fatal("second cgroup linked to a vertex that already has one")
	}
}
