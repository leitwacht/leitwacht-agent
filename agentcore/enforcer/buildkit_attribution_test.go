package enforcer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------- SessionRegistry pure-data tests ----------------

func TestSessionRegistry_RegisterAndSnapshot(t *testing.T) {
	r := NewSessionRegistry(0)
	r.RegisterSession("r1", time.Unix(1000, 0), map[string]string{"target": "build"})

	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot size = %d, want 1", len(snap))
	}

	got := snap["r1"]
	if got.Ref != "r1" {
		t.Fatalf("Ref = %q, want %q", got.Ref, "r1")
	}

	if !got.StartedAt.Equal(time.Unix(1000, 0)) {
		t.Fatalf("StartedAt = %v, want %v", got.StartedAt, time.Unix(1000, 0))
	}

	if got.FrontendAttrs["target"] != "build" {
		t.Fatalf("FrontendAttrs = %v, want {target:build}", got.FrontendAttrs)
	}
}

func TestSessionRegistry_RegisterIdempotent(t *testing.T) {
	r := NewSessionRegistry(0)
	r.RegisterSession("r1", time.Unix(1000, 0), map[string]string{"a": "1"})
	r.RegisterSession("r1", time.Unix(2000, 0), map[string]string{"b": "2"})

	got := r.Snapshot()["r1"]
	if !got.StartedAt.Equal(time.Unix(1000, 0)) {
		t.Fatalf("second Register clobbered StartedAt: got %v", got.StartedAt)
	}

	if got.FrontendAttrs["b"] != "" {
		t.Fatalf("second Register clobbered FrontendAttrs: %v", got.FrontendAttrs)
	}
}

func TestSessionRegistry_UpsertVertex(t *testing.T) {
	r := NewSessionRegistry(0)
	r.RegisterSession("r1", time.Unix(1000, 0), nil)

	r.UpsertVertex("r1", VertexState{
		Digest:    "sha256:abc",
		Name:      "[build 1/2] RUN apt-get update",
		StartedAt: time.Unix(1010, 0),
	})

	// Repeated upsert with the same digest but a Completed marker
	// should advance Completed without clobbering StartedAt.
	r.UpsertVertex("r1", VertexState{
		Digest:      "sha256:abc",
		Completed:   true,
		CompletedAt: time.Unix(1020, 0),
	})

	v := r.Snapshot()["r1"].Vertices["sha256:abc"]
	if v == nil {
		t.Fatal("vertex absent after upsert")
	}

	if v.Name != "[build 1/2] RUN apt-get update" {
		t.Fatalf("Name = %q, want preserved across reupsert", v.Name)
	}

	if !v.StartedAt.Equal(time.Unix(1010, 0)) {
		t.Fatalf("StartedAt clobbered: %v", v.StartedAt)
	}

	if !v.Completed || !v.CompletedAt.Equal(time.Unix(1020, 0)) {
		t.Fatalf("Completed/CompletedAt not advanced: %+v", v)
	}
}

func TestSessionRegistry_UpsertVertexWithoutSession(t *testing.T) {
	// Status event can arrive before BuildHistory STARTED (race).
	// The registry should auto-create a placeholder session.
	r := NewSessionRegistry(0)
	r.UpsertVertex("r-race", VertexState{Digest: "sha256:xyz", Name: "RUN foo"})

	snap := r.Snapshot()
	if _, ok := snap["r-race"]; !ok {
		t.Fatal("placeholder session not created on early vertex")
	}
}

func TestSessionRegistry_SweepDropsCompletedPastCutoff(t *testing.T) {
	r := NewSessionRegistry(time.Minute)
	r.RegisterSession("done", time.Unix(1000, 0), nil)
	r.CompleteSession("done", time.Unix(1500, 0))

	r.RegisterSession("active", time.Unix(1100, 0), nil)

	r.RegisterSession("recent-done", time.Unix(1200, 0), nil)
	r.CompleteSession("recent-done", time.Unix(2000, 0))

	// Cutoff: anything completed before t=1800 should drop.
	dropped := r.Sweep(time.Unix(1800, 0))
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}

	snap := r.Snapshot()
	if _, ok := snap["done"]; ok {
		t.Fatal("expected `done` to be swept")
	}

	if _, ok := snap["active"]; !ok {
		t.Fatal("active session swept (must not happen)")
	}

	if _, ok := snap["recent-done"]; !ok {
		t.Fatal("recently-completed session swept too early")
	}
}

func TestSessionRegistry_DropSessionImmediate(t *testing.T) {
	r := NewSessionRegistry(time.Hour)
	r.RegisterSession("r1", time.Unix(1000, 0), nil)
	r.DropSession("r1")

	if _, ok := r.Snapshot()["r1"]; ok {
		t.Fatal("DropSession did not remove session")
	}
}

// ---------------- AttributionWatcher end-to-end with fake server ----------------

// fakeBuildkitServer implements just enough of controlapi.ControlServer
// to drive the watcher. Tests stage events via the staged* channels
// and then assert what landed in the registry.
type fakeBuildkitServer struct {
	controlapi.UnimplementedControlServer

	mu           sync.Mutex
	historyChans map[string]chan *controlapi.StatusResponse
	historyOut   chan *controlapi.BuildHistoryEvent
	closeAll     chan struct{}
}

func newFakeServer() *fakeBuildkitServer {
	return &fakeBuildkitServer{
		historyChans: make(map[string]chan *controlapi.StatusResponse),
		historyOut:   make(chan *controlapi.BuildHistoryEvent, 16),
		closeAll:     make(chan struct{}),
	}
}

func (f *fakeBuildkitServer) ListenBuildHistory(_ *controlapi.BuildHistoryRequest, srv grpc.ServerStreamingServer[controlapi.BuildHistoryEvent]) error {
	ctx := srv.Context()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-f.closeAll:
			return nil
		case evt := <-f.historyOut:
			if err := srv.Send(evt); err != nil {
				return err
			}
		}
	}
}

func (f *fakeBuildkitServer) Status(req *controlapi.StatusRequest, srv grpc.ServerStreamingServer[controlapi.StatusResponse]) error {
	f.mu.Lock()
	ch, ok := f.historyChans[req.GetRef()]
	if !ok {
		ch = make(chan *controlapi.StatusResponse, 16)
		f.historyChans[req.GetRef()] = ch
	}
	f.mu.Unlock()

	ctx := srv.Context()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-f.closeAll:
			return nil
		case msg, ok := <-ch:
			if !ok {
				return nil
			}

			if err := srv.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (f *fakeBuildkitServer) emitHistory(t *testing.T, evt *controlapi.BuildHistoryEvent) {
	t.Helper()

	select {
	case f.historyOut <- evt:
	case <-time.After(time.Second):
		t.Fatalf("history channel full")
	}
}

func (f *fakeBuildkitServer) emitStatus(t *testing.T, ref string, msg *controlapi.StatusResponse) {
	t.Helper()

	f.mu.Lock()
	ch, ok := f.historyChans[ref]

	if !ok {
		ch = make(chan *controlapi.StatusResponse, 16)
		f.historyChans[ref] = ch
	}
	f.mu.Unlock()

	select {
	case ch <- msg:
	case <-time.After(time.Second):
		t.Fatalf("status channel for ref %s full", ref)
	}
}

func startFakeServer(t *testing.T) (*fakeBuildkitServer, []grpc.DialOption, func()) {
	t.Helper()

	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	fake := newFakeServer()

	controlapi.RegisterControlServer(srv, fake)

	go func() {
		_ = srv.Serve(lis)
	}()

	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	cleanup := func() {
		close(fake.closeAll)
		srv.Stop()
	}

	return fake, dialOpts, cleanup
}

func TestAttributionWatcher_StartedAndStatusFlow(t *testing.T) {
	fake, dialOpts, cleanup := startFakeServer(t)
	defer cleanup()

	reg := NewSessionRegistry(time.Minute)

	w := NewAttributionWatcher(
		"passthrough://bufnet",
		reg,
		nil,
		WithDialOptions(dialOpts...),
		WithSweepInterval(time.Hour),
		WithBackoff(time.Millisecond, time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)

		close(done)
	}()

	// Emit STARTED for ref-A.
	fake.emitHistory(t, &controlapi.BuildHistoryEvent{
		Type: controlapi.BuildHistoryEventType_STARTED,
		Record: &controlapi.BuildHistoryRecord{
			Ref:           "ref-A",
			CreatedAt:     timestamppb.New(time.Unix(1000, 0)),
			FrontendAttrs: map[string]string{"target": "build"},
		},
	})

	// Emit a Status response with a vertex.
	fake.emitStatus(t, "ref-A", &controlapi.StatusResponse{
		Vertexes: []*controlapi.Vertex{
			{
				Digest:  "sha256:vA",
				Name:    "[build 1/2] RUN apt-get update",
				Started: timestamppb.New(time.Unix(1010, 0)),
			},
		},
	})

	// Wait for the registry to pick it up.
	waitFor(t, time.Second, func() bool {
		snap := reg.Snapshot()
		s := snap["ref-A"]

		return s.Ref == "ref-A" && s.Vertices["sha256:vA"] != nil
	})

	v := reg.Snapshot()["ref-A"].Vertices["sha256:vA"]
	if v.Name != "[build 1/2] RUN apt-get update" {
		t.Fatalf("vertex name = %q", v.Name)
	}

	// Emit COMPLETE for the session.
	fake.emitHistory(t, &controlapi.BuildHistoryEvent{
		Type: controlapi.BuildHistoryEventType_COMPLETE,
		Record: &controlapi.BuildHistoryRecord{
			Ref:         "ref-A",
			CompletedAt: timestamppb.New(time.Unix(1020, 0)),
		},
	})

	waitFor(t, time.Second, func() bool {
		return reg.Snapshot()["ref-A"].Completed
	})

	cancel()
	<-done
}

func TestAttributionWatcher_DeletedEventDropsSession(t *testing.T) {
	fake, dialOpts, cleanup := startFakeServer(t)
	defer cleanup()

	reg := NewSessionRegistry(time.Minute)

	w := NewAttributionWatcher(
		"passthrough://bufnet",
		reg,
		nil,
		WithDialOptions(dialOpts...),
		WithSweepInterval(time.Hour),
		WithBackoff(time.Millisecond, time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = w.Run(ctx)
	}()

	fake.emitHistory(t, &controlapi.BuildHistoryEvent{
		Type: controlapi.BuildHistoryEventType_STARTED,
		Record: &controlapi.BuildHistoryRecord{
			Ref:       "ref-D",
			CreatedAt: timestamppb.New(time.Unix(1000, 0)),
		},
	})

	waitFor(t, time.Second, func() bool {
		_, ok := reg.Snapshot()["ref-D"]

		return ok
	})

	fake.emitHistory(t, &controlapi.BuildHistoryEvent{
		Type:   controlapi.BuildHistoryEventType_DELETED,
		Record: &controlapi.BuildHistoryRecord{Ref: "ref-D"},
	})

	waitFor(t, time.Second, func() bool {
		_, ok := reg.Snapshot()["ref-D"]

		return !ok
	})
}

func waitFor(t *testing.T, timeout time.Duration, pred func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("condition not met within %s", timeout)
}

// ---------------- helpers ----------------

func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"tcp://host:1234":   "host:1234",
		"unix:///run/x.sock": "unix:/run/x.sock",
		"host:1234":         "host:1234",
		"unix:/run/x.sock":  "unix:/run/x.sock",
	}

	for in, want := range cases {
		got := stripScheme(in)
		if got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNextBackoff(t *testing.T) {
	if got := nextBackoff(time.Second, 10*time.Second); got != 2*time.Second {
		t.Errorf("doubling: got %v, want 2s", got)
	}

	if got := nextBackoff(8*time.Second, 10*time.Second); got != 10*time.Second {
		t.Errorf("capped at max: got %v, want 10s", got)
	}
}
