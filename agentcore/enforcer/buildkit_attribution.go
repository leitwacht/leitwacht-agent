// Package enforcer — BuildKit step-attribution subscriber.
//
// This file connects to a buildkitd daemon's Control gRPC service and
// maintains a per-session registry of in-flight Dockerfile vertices.
// Phase 2 (cgroup-to-vertex join) reads from the registry to enrich
// runc-spawned RUN containers with their owning vertex; Phase 3
// (event enrichment) reads from it to attach build-step context to
// egress events.
//
// See docs/BUILDKIT_STEP_ATTRIBUTION.md for the full design.
package enforcer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// SessionRegistry holds the in-memory map of build sessions and the
// vertices observed inside each. Mutators are called from the
// AttributionWatcher's stream-consuming goroutines; readers are
// Phase-2 and Phase-3 enrichment paths (added in later commits).
//
// Concurrency: a single sync.RWMutex guards both the sessions map
// and each session's vertices map. Sessions and vertices are small
// (≤ max-parallelism per daemon) and writes happen at the cadence
// of vertex transitions, so coarse locking is fine.
type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState

	// completedTTL controls how long a completed session stays in
	// the registry. Set to a small value (default 30s) so the
	// cgroup-join layer can still attribute tail traffic (cache
	// pushes, layer exports) that fires after the final vertex
	// completes but before runc tears down the container.
	completedTTL time.Duration
}

// SessionState is the per-build view: a build ref plus the vertices
// observed for it. Exported so Phase 2 and Phase 3 can read it; the
// mutator methods on SessionRegistry are the only intended writers.
type SessionState struct {
	Ref         string
	StartedAt   time.Time
	Completed   bool
	CompletedAt time.Time

	// FrontendAttrs is the build's frontend options (build-args,
	// target stage, labels) — captured from BuildHistoryRecord at
	// session-start time. Used by the Phase 2 cgroup-join tiebreaker
	// when multiple sessions have identical vertex command strings.
	FrontendAttrs map[string]string

	Vertices map[string]*VertexState // keyed by digest
}

// VertexState mirrors the fields the agent cares about from
// controlapi.Vertex. Kept independent of the BuildKit proto so the
// registry's public surface doesn't leak generated types.
type VertexState struct {
	Digest      string
	Name        string // human string, e.g. "[build 5/12] RUN npm ci"
	StartedAt   time.Time
	Completed   bool
	CompletedAt time.Time
	Cached      bool
}

// NewSessionRegistry returns an empty registry. completedTTL governs
// how long completed sessions stay in the map; a zero value applies
// a sensible 30s default.
func NewSessionRegistry(completedTTL time.Duration) *SessionRegistry {
	if completedTTL <= 0 {
		completedTTL = 30 * time.Second
	}

	return &SessionRegistry{
		sessions:     make(map[string]*SessionState),
		completedTTL: completedTTL,
	}
}

// RegisterSession records a STARTED event from ListenBuildHistory.
// Idempotent on repeated calls for the same ref (a reconnect after
// disconnect replays in-flight sessions).
func (r *SessionRegistry) RegisterSession(ref string, startedAt time.Time, attrs map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sessions[ref]; exists {
		return
	}

	r.sessions[ref] = &SessionState{
		Ref:           ref,
		StartedAt:     startedAt,
		FrontendAttrs: attrs,
		Vertices:      make(map[string]*VertexState),
	}
}

// CompleteSession marks a session COMPLETE. The session stays in the
// registry for completedTTL afterwards (so tail-traffic enrichment
// still resolves), then becomes eligible for sweep.
func (r *SessionRegistry) CompleteSession(ref string, completedAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[ref]
	if !ok {
		return
	}

	s.Completed = true
	s.CompletedAt = completedAt
}

// DropSession removes a session immediately (DELETED event from
// BuildKit's history API). Bypasses the completedTTL grace.
func (r *SessionRegistry) DropSession(ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, ref)
}

// UpsertVertex creates or updates a vertex within a session. Called
// for every Vertex in every StatusResponse — the same vertex appears
// multiple times as it progresses (started → completed).
func (r *SessionRegistry) UpsertVertex(ref string, v VertexState) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[ref]
	if !ok {
		// Session not yet known (race: Status arrived before
		// BuildHistory STARTED). Create a placeholder; the
		// subsequent STARTED will populate FrontendAttrs.
		s = &SessionState{
			Ref:      ref,
			Vertices: make(map[string]*VertexState),
		}
		r.sessions[ref] = s
	}

	existing, ok := s.Vertices[v.Digest]
	if !ok {
		copy := v
		s.Vertices[v.Digest] = &copy

		return
	}

	// Preserve the earliest StartedAt observed (later Status events
	// repeat the value but a transient zero would clobber it).
	if !v.StartedAt.IsZero() {
		existing.StartedAt = v.StartedAt
	}

	if v.Name != "" {
		existing.Name = v.Name
	}

	if v.Cached {
		existing.Cached = true
	}

	if v.Completed && !existing.Completed {
		existing.Completed = true
		existing.CompletedAt = v.CompletedAt
	}
}

// Sweep removes sessions completed before cutoff. Call periodically
// from a separate goroutine (the watcher's Run loop wires this up).
func (r *SessionRegistry) Sweep(cutoff time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var dropped int

	for ref, s := range r.sessions {
		if s.Completed && s.CompletedAt.Before(cutoff) {
			delete(r.sessions, ref)
			dropped++
		}
	}

	return dropped
}

// Snapshot returns a defensive copy of the current registry state.
// Used by tests and the metrics surface; not on the hot path.
func (r *SessionRegistry) Snapshot() map[string]SessionState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]SessionState, len(r.sessions))
	for ref, s := range r.sessions {
		copy := SessionState{
			Ref:           s.Ref,
			StartedAt:     s.StartedAt,
			Completed:     s.Completed,
			CompletedAt:   s.CompletedAt,
			FrontendAttrs: cloneStringMap(s.FrontendAttrs),
			Vertices:      make(map[string]*VertexState, len(s.Vertices)),
		}

		for digest, v := range s.Vertices {
			vc := *v
			copy.Vertices[digest] = &vc
		}

		out[ref] = copy
	}

	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}

	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}

	return out
}

// AttributionWatcher connects to a buildkitd daemon over gRPC and
// pumps Control.ListenBuildHistory + Control.Status events into the
// supplied SessionRegistry. Reconnects with capped exponential
// backoff on disconnect.
//
// The watcher does not own the registry — callers wire one registry
// across the watcher, Phase 2's cgroup-join, and Phase 3's event
// enrichment.
type AttributionWatcher struct {
	addr     string
	registry *SessionRegistry
	logger   *slog.Logger

	// dialOpts is exposed for tests (in-memory grpc.ClientConn).
	// Production callers leave it nil and the watcher applies the
	// default plaintext + keepalive options.
	dialOpts []grpc.DialOption

	// Reconnect backoff. Defaults: min 1s, max 60s, growth 2x.
	minBackoff time.Duration
	maxBackoff time.Duration

	// sweepInterval governs how often Sweep is called to GC
	// completed sessions. Default 1m.
	sweepInterval time.Duration
}

// WatcherOption tunes an AttributionWatcher at construction.
type WatcherOption func(*AttributionWatcher)

// WithDialOptions overrides the gRPC dial options. Intended for
// tests that wire an in-memory bufconn; production deployments
// should leave the defaults alone.
func WithDialOptions(opts ...grpc.DialOption) WatcherOption {
	return func(w *AttributionWatcher) { w.dialOpts = opts }
}

// WithBackoff overrides the reconnect backoff bounds.
func WithBackoff(minB, maxB time.Duration) WatcherOption {
	return func(w *AttributionWatcher) {
		w.minBackoff = minB
		w.maxBackoff = maxB
	}
}

// WithSweepInterval overrides the session-sweep cadence.
func WithSweepInterval(d time.Duration) WatcherOption {
	return func(w *AttributionWatcher) { w.sweepInterval = d }
}

// NewAttributionWatcher constructs a watcher; call Run to start it.
// addr is the buildkitd gRPC endpoint (tcp://host:port,
// unix:///path/to/sock, or any grpc.NewClient-acceptable target —
// the "tcp://"/"unix://" scheme is stripped before dialing).
func NewAttributionWatcher(addr string, registry *SessionRegistry, logger *slog.Logger, opts ...WatcherOption) *AttributionWatcher {
	if logger == nil {
		logger = slog.Default()
	}

	w := &AttributionWatcher{
		addr:          addr,
		registry:      registry,
		logger:        logger,
		minBackoff:    time.Second,
		maxBackoff:    time.Minute,
		sweepInterval: time.Minute,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Run blocks until ctx is cancelled, repeatedly connecting to
// buildkitd and pumping history + status events into the registry.
// Returns ctx.Err() on cancellation; any other return value is a
// programmer error (panic conditions surface via the logger).
//
//nolint:gocognit,cyclop // single-state-machine reconnect loop reads cleanly top-to-bottom
func (w *AttributionWatcher) Run(ctx context.Context) error {
	go w.sweepLoop(ctx)

	backoff := w.minBackoff

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		conn, err := w.connect(ctx)
		if err != nil {
			w.logger.Warn("buildkit connect failed", "addr", w.addr, "err", err, "backoff", backoff)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			backoff = nextBackoff(backoff, w.maxBackoff)

			continue
		}

		// Connected; reset backoff before consuming.
		backoff = w.minBackoff

		client := controlapi.NewControlClient(conn)

		err = w.listenHistory(ctx, client)

		_ = conn.Close()

		// Cancelled context propagates as ctx.Err; any other error
		// triggers reconnect. listenHistory returns nil on a clean
		// stream EOF (BuildKit closed the stream — happens on
		// daemon restart).
		if errors.Is(err, context.Canceled) {
			return err
		}

		if err != nil {
			w.logger.Warn("buildkit history stream ended", "err", err)
		}
	}
}

func (w *AttributionWatcher) connect(_ context.Context) (*grpc.ClientConn, error) {
	target := stripScheme(w.addr)

	opts := w.dialOpts
	if opts == nil {
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
	}

	// grpc.NewClient does not connect synchronously; the connection
	// is established lazily on the first RPC. The subsequent
	// ListenBuildHistory call is where dial failures surface, and
	// they're handled by the outer reconnect loop.
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("buildkit client for %s: %w", target, err)
	}

	return conn, nil
}

// listenHistory subscribes to ListenBuildHistory(ActiveOnly=true)
// and dispatches per-ref Status streams in their own goroutines.
// Returns nil on clean EOF, ctx.Err() on cancellation, or the
// underlying error otherwise.
func (w *AttributionWatcher) listenHistory(ctx context.Context, client controlapi.ControlClient) error {
	stream, err := client.ListenBuildHistory(ctx, &controlapi.BuildHistoryRequest{ActiveOnly: true})
	if err != nil {
		return fmt.Errorf("listen build history: %w", err)
	}

	for {
		evt, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return err //nolint:wrapcheck // surfaced to the reconnect loop verbatim
		}

		w.handleHistoryEvent(ctx, client, evt)
	}
}

func (w *AttributionWatcher) handleHistoryEvent(ctx context.Context, client controlapi.ControlClient, evt *controlapi.BuildHistoryEvent) {
	rec := evt.GetRecord()
	if rec == nil {
		return
	}

	ref := rec.GetRef()
	if ref == "" {
		return
	}

	switch evt.GetType() {
	case controlapi.BuildHistoryEventType_STARTED:
		startedAt := time.Now()
		if ts := rec.GetCreatedAt(); ts != nil {
			startedAt = ts.AsTime()
		}

		w.registry.RegisterSession(ref, startedAt, rec.GetFrontendAttrs())

		go w.streamStatus(ctx, client, ref)
	case controlapi.BuildHistoryEventType_COMPLETE:
		completedAt := time.Now()
		if ts := rec.GetCompletedAt(); ts != nil {
			completedAt = ts.AsTime()
		}

		w.registry.CompleteSession(ref, completedAt)
	case controlapi.BuildHistoryEventType_DELETED:
		w.registry.DropSession(ref)
	}
}

// streamStatus subscribes to Status for a single build ref and
// pumps vertex transitions into the registry. Returns when the
// stream closes (build completes), ctx is cancelled, or an error
// surfaces — the parent listenHistory keeps running independently.
func (w *AttributionWatcher) streamStatus(ctx context.Context, client controlapi.ControlClient, ref string) {
	stream, err := client.Status(ctx, &controlapi.StatusRequest{Ref: ref})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			w.logger.Debug("buildkit status open failed", "ref", ref, "err", err)
		}

		return
	}

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return
		}

		if err != nil {
			w.logger.Debug("buildkit status stream ended", "ref", ref, "err", err)

			return
		}

		for _, v := range msg.GetVertexes() {
			w.registry.UpsertVertex(ref, vertexFromProto(v))
		}
	}
}

func vertexFromProto(v *controlapi.Vertex) VertexState {
	out := VertexState{
		Digest: v.GetDigest(),
		Name:   v.GetName(),
		Cached: v.GetCached(),
	}

	if ts := v.GetStarted(); ts != nil {
		out.StartedAt = ts.AsTime()
	}

	if ts := v.GetCompleted(); ts != nil {
		out.Completed = true
		out.CompletedAt = ts.AsTime()
	}

	return out
}

func (w *AttributionWatcher) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(w.sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			dropped := w.registry.Sweep(now.Add(-w.registry.completedTTL))
			if dropped > 0 {
				w.logger.Debug("buildkit registry sweep", "dropped", dropped)
			}
		}
	}
}

func nextBackoff(current, maxB time.Duration) time.Duration {
	next := current * 2
	if next > maxB {
		next = maxB
	}

	return next
}

// stripScheme removes "tcp://" or "unix://" prefixes so the address
// is acceptable to grpc.DialContext (which expects host:port or
// unix:/path, not tcp://host:port).
func stripScheme(addr string) string {
	const (
		tcpPrefix  = "tcp://"
		unixPrefix = "unix://"
	)

	switch {
	case len(addr) > len(tcpPrefix) && addr[:len(tcpPrefix)] == tcpPrefix:
		return addr[len(tcpPrefix):]
	case len(addr) > len(unixPrefix) && addr[:len(unixPrefix)] == unixPrefix:
		return "unix:" + addr[len(unixPrefix):]
	default:
		return addr
	}
}
