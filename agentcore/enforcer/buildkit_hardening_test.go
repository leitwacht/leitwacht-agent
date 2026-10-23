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
	r.sessions["old"].registeredAt = time.Now().Add(-2 * time.Hour)
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

func TestCgroupJoiner_NoMatchKillsOnlyWhenEnforcing(t *testing.T) {
	t.Run("enforcing", func(t *testing.T) {
		reg := NewSessionRegistry(time.Minute)
		reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{regexp.MustCompile(`RUN never-matches`)})

		h := newJoinHarness(t, reg, 100*time.Millisecond)
		cg := h.stage(t, "ctr-x", 12, "/bin/sh\x00-c\x00curl http://evil.example\x00")
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-x", CgroupPath: cg}

		waitFor(t, 2*time.Second, h.killed)
	})

	t.Run("default config unchanged", func(t *testing.T) {
		reg := NewSessionRegistry(time.Minute)

		h := newJoinHarness(t, reg, 60*time.Millisecond)
		cg := h.stage(t, "ctr-y", 13, "/bin/sh\x00-c\x00whatever\x00")
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-y", CgroupPath: cg}

		time.Sleep(300 * time.Millisecond)

		if h.killed() {
			t.Fatal("cgroup killed with no kill policy configured")
		}
	})
}

func TestCgroupJoiner_SubstringOfOtherSessionDoesNotInherit(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})

	reg.RegisterSession("rGood", time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/p"})
	reg.UpsertVertex("rGood", VertexState{Digest: "dG", Name: "[s 1/1] RUN npm ci", StartedAt: time.Unix(2, 0)})

	h := newJoinHarness(t, reg, 80*time.Millisecond)
	// A process that merely contains the authorized RUN text.
	cg := h.stage(t, "ctr-sub", 14, "/bin/sh\x00-c\x00npm ci; curl http://evil.example\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-sub", CgroupPath: cg}

	waitFor(t, 2*time.Second, h.killed)

	if _, ok := reg.LookupByCgroupID(4321); ok {
		t.Fatal("substring match must not bind to the authorized session")
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
