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
	"sync/atomic"
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

	// cgroupIndex is the hot-path lookup: kernel cgroup_id (the
	// inode of the cgroup directory) -> the build context that
	// owns the runc container occupying that cgroup. Populated by
	// the cgroup-join layer (Phase 2) and read by egress event
	// enrichment (Phase 3).
	cgroupIndex map[uint64]CgroupBinding

	// completedTTL controls how long a completed session stays in
	// the registry. Set to a small value (default 30s) so the
	// cgroup-join layer can still attribute tail traffic (cache
	// pushes, layer exports) that fires after the final vertex
	// completes but before runc tears down the container.
	completedTTL time.Duration

	// requireCIMetadata, when true, marks a session as Unauthorized
	// at RegisterSession time if any requiredAttrs key is missing
	// from the session's FrontendAttrs. The cgroup-join layer kills
	// (SIGKILL via cgroup.kill) RUN cgroups linked to unauthorized
	// sessions before they can do any egress. When false (default)
	// every session is authorized — back-compat for installations
	// that haven't opted into hard policy enforcement yet.
	requireCIMetadata bool
	requiredAttrs     []string // FrontendAttrs keys, already prefixed (e.g. "build-arg:LEITWACHT_CI_PROJECT_PATH")
}

// CgroupBinding ties a kernel cgroup_id to the build session and
// vertex that own the runc container occupying that cgroup. Returned
// by SessionRegistry.LookupByCgroupID; used by egress event
// enrichment to attach BuildStepAttribution to outgoing violations.
type CgroupBinding struct {
	SessionRef    string
	VertexDigest  string
	VertexName    string
	ContainerID   string // runc container id (also the cgroup directory name)
	LinkedAt      time.Time
	FrontendAttrs map[string]string

	// Ambiguous is true when the cgroup-join couldn't disambiguate
	// between multiple concurrent vertices with identical command
	// strings. AmbiguousCandidates lists the colliding (ref,
	// digest) tuples for forensics. When Ambiguous is true, the
	// VertexDigest/Name fields are not authoritative.
	Ambiguous           bool
	AmbiguousCandidates []AmbiguousCandidate
}

// AmbiguousCandidate is one of the colliding vertex candidates when
// the cgroup-join couldn't pin a cgroup to a single vertex.
type AmbiguousCandidate struct {
	SessionRef   string
	VertexDigest string
	VertexName   string
}

// Reserved FrontendAttrs build-arg keys the agent reads to override
// per-row CI fields. The CI runner passes these via
// `docker buildx build --build-arg LEITWACHT_CI_PROJECT_PATH=...` so
// the agent can attribute each Solve session to its CI job rather
// than to the (shared) buildkitd container's own labels. BuildKit
// prefixes build-args with "build-arg:" in the FrontendAttrs map.
const (
	frontendAttrBuildArgPrefix = "build-arg:"

	FrontendAttrKeyProjectPath = frontendAttrBuildArgPrefix + "LEITWACHT_CI_PROJECT_PATH"
	FrontendAttrKeyJobID       = frontendAttrBuildArgPrefix + "LEITWACHT_CI_JOB_ID"
	FrontendAttrKeyPipelineID  = frontendAttrBuildArgPrefix + "LEITWACHT_CI_PIPELINE_ID"
	FrontendAttrKeyJobName     = frontendAttrBuildArgPrefix + "LEITWACHT_CI_JOB_NAME"
	FrontendAttrKeyJobStage    = frontendAttrBuildArgPrefix + "LEITWACHT_CI_JOB_STAGE"
	FrontendAttrKeyGitRef      = frontendAttrBuildArgPrefix + "LEITWACHT_CI_GIT_REF"
	FrontendAttrKeyJobURL      = frontendAttrBuildArgPrefix + "LEITWACHT_CI_JOB_URL"
)

// CIOverrideFromFrontendAttrs extracts the per-row CI override fields
// the agent stamps onto egress violations. Returns zero values when
// the attrs map carries none of the reserved keys; callers should
// branch on whether any field is non-empty to decide if an override
// applies. Cheap: 7 map lookups; called per egress event on the
// BuildKit-attributed hot path.
func CIOverrideFromFrontendAttrs(attrs map[string]string) (projectPath, jobID, pipelineID, jobName, jobStage, gitRef, jobURL string) {
	if len(attrs) == 0 {
		return
	}

	projectPath = attrs[FrontendAttrKeyProjectPath]
	jobID = attrs[FrontendAttrKeyJobID]
	pipelineID = attrs[FrontendAttrKeyPipelineID]
	jobName = attrs[FrontendAttrKeyJobName]
	jobStage = attrs[FrontendAttrKeyJobStage]
	gitRef = attrs[FrontendAttrKeyGitRef]
	jobURL = attrs[FrontendAttrKeyJobURL]

	return
}

// buildKitLookup is the hot-path cgroup-to-binding hook called by
// the eBPF event handler on every egress packet. The no-op default
// keeps non-BuildKit deployments cost-free; the SessionRegistry's
// owner installs the real lookup via SetBuildKitLookup at startup.
//
//nolint:gochecknoglobals // package-level hook avoids plumbing a registry through every event-handler call site.
var buildKitLookup atomic.Pointer[func(uint64) (CgroupBinding, bool)]

// SetBuildKitLookup installs the cgroup-to-binding lookup hook. Pass
// SessionRegistry.LookupByCgroupID from the agent's startup wiring.
// Passing nil restores the no-op default (useful for tests and for
// shutdown ordering).
func SetBuildKitLookup(fn func(cgroupID uint64) (CgroupBinding, bool)) {
	if fn == nil {
		buildKitLookup.Store(nil)

		return
	}

	buildKitLookup.Store(&fn)
}

// LookupBuildKitBinding queries the installed hook. Returns
// (zero, false) when no hook is installed or no binding is known
// for the cgroup. Cheap enough to call on every egress event.
func LookupBuildKitBinding(cgroupID uint64) (CgroupBinding, bool) {
	fn := buildKitLookup.Load()
	if fn == nil {
		return CgroupBinding{}, false
	}

	return (*fn)(cgroupID)
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

	// Authorized is the kill-switch decision computed at
	// RegisterSession time from the registry's require-CI-metadata
	// policy. True when policy is disabled OR all required
	// FrontendAttrs keys are present. False marks the session for
	// cgroup-level termination by the join layer.
	Authorized bool
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
		cgroupIndex:  make(map[uint64]CgroupBinding),
		completedTTL: completedTTL,
	}
}

// LinkCgroup records that the cgroup with the given id holds the runc
// container for (ref, vertexDigest). Called by the cgroup-join layer
// after a successful match. Idempotent on repeated calls for the
// same cgroup_id (later calls overwrite — the latest match wins,
// which matters for runc container ID reuse across builds).
func (r *SessionRegistry) LinkCgroup(cgroupID uint64, binding CgroupBinding) {
	if binding.LinkedAt.IsZero() {
		binding.LinkedAt = time.Now()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cgroupIndex[cgroupID] = binding
}

// UnlinkCgroup removes a cgroup-to-vertex binding. Called when the
// cgroup directory is removed (runc cleanup after RUN completes).
// Cheap no-op if the cgroup isn't tracked.
func (r *SessionRegistry) UnlinkCgroup(cgroupID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cgroupIndex, cgroupID)
}

// LookupByCgroupID returns the binding for a cgroup, or false when
// the cgroup isn't tracked (the common case — most egress events
// fire from cgroups outside BuildKit's tree).
func (r *SessionRegistry) LookupByCgroupID(cgroupID uint64) (CgroupBinding, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	binding, ok := r.cgroupIndex[cgroupID]

	return binding, ok
}

// CgroupSnapshot returns a copy of the current cgroup_id → binding
// map. Intended for observability (dev probes, metrics gauges) — the
// hot-path egress lookup uses LookupByCgroupID instead. Cheap on
// non-BuildKit deployments because the map stays empty.
func (r *SessionRegistry) CgroupSnapshot() map[uint64]CgroupBinding {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[uint64]CgroupBinding, len(r.cgroupIndex))
	for k, v := range r.cgroupIndex {
		out[k] = v
	}

	return out
}

// PendingVertices returns vertices that have started but not yet
// completed across all active sessions. Used by the cgroup-join
// layer to match cmdline strings against in-flight build steps.
// Returns the join's view of the active set; the registry's mutex
// is held only for the snapshot, not the caller's match loop.
func (r *SessionRegistry) PendingVertices() []PendingVertex {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []PendingVertex

	for _, s := range r.sessions {
		for _, v := range s.Vertices {
			if v.Completed {
				continue
			}

			if v.StartedAt.IsZero() {
				continue
			}

			out = append(out, PendingVertex{
				SessionRef:    s.Ref,
				VertexDigest:  v.Digest,
				VertexName:    v.Name,
				FrontendAttrs: cloneStringMap(s.FrontendAttrs),
				Authorized:    s.Authorized,
			})
		}
	}

	return out
}

// PendingVertex is the join-layer's view of an in-flight vertex.
// Carries the human name (used for cmdline matching), the session's
// FrontendAttrs (used as the tiebreaker on collisions), and the
// session's Authorized flag (kill-switch input for the join layer).
type PendingVertex struct {
	SessionRef    string
	VertexDigest  string
	VertexName    string
	FrontendAttrs map[string]string
	Authorized    bool
}

// SetCIRequirement configures the registry's kill-switch policy.
// When require is true, sessions whose FrontendAttrs lack any of
// requiredKeys (already FrontendAttrs-prefixed — typically
// "build-arg:LEITWACHT_CI_PROJECT_PATH") are marked Unauthorized at
// RegisterSession time; the cgroup-join layer then SIGKILLs their
// RUN cgroups via cgroup.kill before any egress can happen. When
// require is false (default), every session is authorized — no
// behaviour change for installations that haven't opted in.
//
// Safe to call before AttributionWatcher.Run; should not be called
// while sessions are actively being registered.
func (r *SessionRegistry) SetCIRequirement(require bool, requiredKeys []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requireCIMetadata = require
	r.requiredAttrs = append([]string(nil), requiredKeys...) // defensive copy
}

// evaluateAuthorization checks whether the session's FrontendAttrs
// satisfy the registry's require-CI-metadata policy. Returns true
// when policy is disabled OR every required key has a non-empty
// value in attrs. Caller must hold r.mu.
func (r *SessionRegistry) evaluateAuthorization(attrs map[string]string) bool {
	if !r.requireCIMetadata {
		return true
	}

	for _, key := range r.requiredAttrs {
		if attrs[key] == "" {
			return false
		}
	}

	return true
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
		Authorized:    r.evaluateAuthorization(attrs),
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
			Authorized:    s.Authorized,
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
