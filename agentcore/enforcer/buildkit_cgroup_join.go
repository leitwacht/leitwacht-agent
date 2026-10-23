package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CgroupCreateEvent is the signal emitted by the platform-specific
// event source when a new cgroup directory appears under a watched
// buildkit-cgroup-parent path. The cgroup name (== runc container
// ID) is in ContainerID; CgroupPath is the absolute path of the
// newly-created directory.
type CgroupCreateEvent struct {
	ContainerID string
	CgroupPath  string
}

// CgroupRemoveEvent fires when a watched cgroup directory disappears
// (runc tearing down a finished RUN container). The join layer
// uses this to unlink the cgroup_id binding so the index doesn't
// grow unbounded.
type CgroupRemoveEvent struct {
	ContainerID string
	CgroupPath  string
}

// CgroupEventSource is the platform abstraction. Linux provides an
// inotify-backed implementation in buildkit_cgroup_join_linux.go;
// non-Linux platforms get a stub that returns ErrCgroupJoinUnsupported.
type CgroupEventSource interface {
	// Run consumes the source's lifetime: it blocks until ctx is
	// cancelled or a fatal error surfaces. Implementations send on
	// creates/removes as events arrive. Channels are closed on
	// Run exit.
	Run(ctx context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) error
}

// ErrCgroupJoinUnsupported is returned by the stub event source on
// non-Linux builds, and by the Linux event source when no watch
// paths are configured.
var ErrCgroupJoinUnsupported = errors.New("buildkit cgroup join is not supported on this platform or no watch paths configured")

// defaultStatFn is the platform-resolved cgroup-id stat function.
// On Linux it returns the inode of the cgroup directory (cgroup v2
// uses the inode as the cgroup_id); on non-Linux it returns
// ErrCgroupJoinUnsupported. Build-tagged init() in
// buildkit_cgroup_join_{linux,stub}.go sets it.
var defaultStatFn func(path string) (uint64, error)

// CgroupJoiner is the orchestrator: it owns the event source, reads
// each new cgroup's first PID's cmdline, matches against pending
// vertices in the SessionRegistry, and links the resulting binding.
//
// Concurrency: a single goroutine consumes events serially. Matching
// against the registry is read-only on the registry's mutex; linking
// is a single write. The event source produces creates/removes on
// buffered channels so a slow match path can't drop kernel events
// (the buffer is sized to the configured channel capacity).
type CgroupJoiner struct {
	registry *SessionRegistry
	logger   *slog.Logger
	source   CgroupEventSource

	// channelBuffer controls the create/remove channel capacity.
	// Default 256 — generous given typical max-parallelism per
	// buildkitd is in the low tens.
	channelBuffer int

	// procRoot is "/proc" in production; tests override.
	procRoot string

	// statFn returns (inode, err) for a cgroup path. Defaults to
	// os.Stat + Sys().Ino via the platform helper; tests override
	// to inject deterministic ids.
	statFn func(path string) (uint64, error)

	// deferredMatchTimeout caps how long we keep retrying a
	// procs-read + cmdline-match for a freshly-created cgroup.
	// BuildKit's OCI executor creates the cgroup directory before
	// the runc child PID is moved into it AND before the Status
	// stream announces the vertex (~100-200ms gap observed in
	// practice). Retrying covers both races. Zero disables retry.
	deferredMatchTimeout time.Duration

	// deferredMatchInterval is the poll interval inside the retry
	// loop. Trade-off: too short wastes CPU on cgroups that will
	// never match (internal BuildKit containers); too long misses
	// fast RUNs. 100ms catches typical timing comfortably.
	deferredMatchInterval time.Duration

	// inflight tracks active deferred-match goroutines keyed by
	// ContainerID. handleRemove uses it to cancel the goroutine
	// and wait for it to exit before doing the unlink walk, so a
	// goroutine that wins its retry after the remove fired can't
	// re-link a binding for a runc container that's already gone.
	inflight sync.Map
}

// pendingDeferredMatch is the handle on one in-flight deferred-match
// goroutine. cancel signals the goroutine to give up; done closes
// when the goroutine returns.
type pendingDeferredMatch struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// JoinerOption tunes a CgroupJoiner at construction.
type JoinerOption func(*CgroupJoiner)

// WithProcRoot overrides the /proc mount path. Test-only.
func WithProcRoot(root string) JoinerOption {
	return func(j *CgroupJoiner) { j.procRoot = root }
}

// WithStatFn overrides the cgroup-id resolver. Test-only.
func WithStatFn(fn func(path string) (uint64, error)) JoinerOption {
	return func(j *CgroupJoiner) { j.statFn = fn }
}

// WithChannelBuffer overrides the create/remove channel capacity.
func WithChannelBuffer(n int) JoinerOption {
	return func(j *CgroupJoiner) { j.channelBuffer = n }
}

// WithDeferredMatch sets how long the joiner keeps retrying a
// match for a freshly-created cgroup, and the interval between
// attempts. Zero timeout disables retry (legacy behaviour: a single
// match attempt at cgroup-create time, drop on empty procs or no
// pending vertex). Production default is 2s/100ms.
func WithDeferredMatch(timeout, interval time.Duration) JoinerOption {
	return func(j *CgroupJoiner) {
		j.deferredMatchTimeout = timeout
		j.deferredMatchInterval = interval
	}
}

// NewCgroupJoiner returns a joiner wired to the supplied registry
// and platform event source.
func NewCgroupJoiner(registry *SessionRegistry, source CgroupEventSource, logger *slog.Logger, opts ...JoinerOption) *CgroupJoiner {
	if logger == nil {
		logger = slog.Default()
	}

	j := &CgroupJoiner{
		registry:              registry,
		logger:                logger,
		source:                source,
		channelBuffer:         256,
		procRoot:              "/proc",
		statFn:                defaultStatFn,
		deferredMatchTimeout:  2 * time.Second,
		deferredMatchInterval: 100 * time.Millisecond,
	}

	for _, opt := range opts {
		opt(j)
	}

	// Let the registry verify bindings against the cgroup's current
	// inode on lookup (guards against cgroup id reuse after a missed
	// remove event).
	if j.statFn != nil && registry != nil {
		registry.SetStatFn(j.statFn)
	}

	return j
}

// Run blocks until ctx is cancelled or the event source returns a
// fatal error. Per-event errors (cgroup gone, PID exited, cmdline
// unreadable) are logged at debug level and skipped — the create
// event likely fired for something that wasn't a runc RUN container,
// which is normal and harmless.
func (j *CgroupJoiner) Run(ctx context.Context) error {
	creates := make(chan CgroupCreateEvent, j.channelBuffer)
	removes := make(chan CgroupRemoveEvent, j.channelBuffer)

	sourceErr := make(chan error, 1)
	go func() {
		sourceErr <- j.source.Run(ctx, creates, removes)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sourceErr:
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("cgroup event source: %w", err)
			}

			return nil
		case evt, ok := <-creates:
			if !ok {
				return nil
			}

			j.handleCreate(ctx, evt)
		case evt, ok := <-removes:
			if !ok {
				return nil
			}

			j.handleRemove(evt)
		}
	}
}

func (j *CgroupJoiner) handleCreate(ctx context.Context, evt CgroupCreateEvent) {
	cgroupID, err := j.statFn(evt.CgroupPath)
	if err != nil {
		// Cgroup may have been removed already (very short-lived
		// containers). Not interesting at info level.
		j.logger.Debug("cgroup stat failed", "path", evt.CgroupPath, "err", err)

		return
	}

	// First attempt runs synchronously so the happy fast-path
	// (cgroup already populated, vertex already announced) takes
	// no goroutine. The deferred loop only spawns when this misses.
	if j.tryMatch(ctx, cgroupID, evt, j.deferredMatchTimeout <= 0) {
		return
	}

	if j.deferredMatchTimeout <= 0 {
		// No retry window: the single attempt above was final. Egress
		// events for this cgroup will be emitted unattributed.
		return
	}

	// Register an inflight entry so a concurrent handleRemove for
	// this ContainerID can cancel the goroutine and wait for it to
	// exit before doing its unlink walk.
	pendingCtx, cancel := context.WithCancel(ctx)
	pending := &pendingDeferredMatch{
		cancel: cancel,
		done:   make(chan struct{}),
	}

	// runc reuses container IDs across builds (rare but possible). If a
	// previous deferred match for the same ID is still in flight, cancel
	// it before replacing — leaving two goroutines racing for the same
	// ContainerID would re-introduce the leak we're trying to fix.
	if prev, loaded := j.inflight.Swap(evt.ContainerID, pending); loaded {
		pp := prev.(*pendingDeferredMatch)
		pp.cancel()
		<-pp.done
	}

	go func() {
		defer close(pending.done)
		defer j.inflight.CompareAndDelete(evt.ContainerID, pending)

		j.deferredMatch(pendingCtx, cgroupID, evt)
	}()
}

// tryMatch performs one read-procs + read-argv + match-pending
// attempt. Returns true if the cgroup was handled (linked or killed)
// OR if ctx has been cancelled by a remove fired during the retry
// window — in either case the caller's retry loop should stop.
// Returns false on a real miss (procs empty, argv unreadable, no
// pending vertex), so the retry loop keeps trying.
//
// final marks the last attempt for this cgroup. When the operator has
// opted into enforcement (require-CI-metadata or deny patterns) a
// final attempt that finds no single authorized match kills the
// cgroup: an unattributable RUN container must not run unchecked.
// Without enforcement a miss only leaves the cgroup unbound.
func (j *CgroupJoiner) tryMatch(ctx context.Context, cgroupID uint64, evt CgroupCreateEvent, final bool) bool {
	pid, err := readFirstPID(evt.CgroupPath)
	if err != nil {
		return j.noMatch(ctx, cgroupID, evt, final)
	}

	argv, err := readArgv(j.procRoot, pid)
	if err != nil {
		return j.noMatch(ctx, cgroupID, evt, final)
	}

	pending := j.registry.PendingVertices()
	matches := matchPendingByArgv(pending, argv)

	// Final check just before committing: if a remove event for this
	// container fired during the retry window, ctx is now cancelled and
	// we must NOT write a binding. handleRemove will have run its
	// unlink walk against an empty index — no second sweep needed.
	if len(matches) > 0 && ctx.Err() != nil {
		return true
	}

	// A candidate whose history record has not arrived yet has no real
	// authorization decision. Keep retrying until the deadline instead
	// of killing (or trusting) on the placeholder's defaults.
	if !final && anyPlaceholder(matches) {
		return false
	}

	switch len(matches) {
	case 0:
		return j.noMatch(ctx, cgroupID, evt, final)
	case 1:
		m := matches[0]

		// Kill-switch: when the matched session was marked Unauthorized
		// at register time (require-CI-metadata policy enabled and the
		// session's FrontendAttrs lacked a required key), SIGKILL every
		// process in this cgroup via cgroup.kill BEFORE writing a
		// binding.
		if !m.Authorized {
			j.killMatched(cgroupID, evt, m, "buildkit cgroup killed: session missing required CI attribution", 0)

			return true
		}

		// Per-vertex kill-switch: server policy can install regex
		// patterns matching vertex_name (e.g. "RUN npm install"). A
		// match SIGKILLs the cgroup, same mechanism as the missing-
		// CI-metadata path above. Skipped when no patterns are
		// installed — back-compat for installations that haven't
		// opted into per-vertex policy.
		if j.registry.MatchesDenyVertexPattern(m.VertexName) {
			j.killMatched(cgroupID, evt, m, "buildkit cgroup killed: vertex matched a deny policy pattern", 0)

			return true
		}

		j.link(cgroupID, evt, m)

		j.logger.Info("buildkit cgroup linked",
			"cgroup_id", cgroupID,
			"container_id", evt.ContainerID,
			"session_ref", m.SessionRef,
			"vertex_digest", m.VertexDigest,
			"vertex_name_hash", vertexNameHash(m.VertexName),
		)

		return true
	default:
		// Fail-closed policy check: when the join can't pick one
		// candidate, ANY candidate that is unauthorized or whose
		// vertex_name matches a deny pattern kills the cgroup. An
		// attacker who engineers a duplicate vertex name on a benign
		// session would otherwise slip past the single-match checks by
		// landing in ambiguous-link territory. Run this BEFORE the
		// tiebreaker so it also covers the refined-to-one outcome
		// below (the refined candidate is one of these).
		for i := range matches {
			if !matches[i].Authorized {
				j.killMatched(cgroupID, evt, matches[i], "buildkit cgroup killed: ambiguous candidate missing required CI attribution", len(matches))

				return true
			}

			if j.registry.MatchesDenyVertexPattern(matches[i].VertexName) {
				j.killMatched(cgroupID, evt, matches[i], "buildkit cgroup killed: ambiguous candidate matched a deny policy pattern", len(matches))

				return true
			}
		}

		// Tiebreaker: environ. Read /proc/<pid>/environ and pick
		// the candidate whose FrontendAttrs values appear in the
		// process environment. Falls through to ambiguous if the
		// tiebreaker also yields >1 (or 0 — the more likely case
		// when neither side's attrs surface in env).
		environ, _ := readEnviron(j.procRoot, pid)

		refined := tiebreakByEnviron(matches, environ)
		if len(refined) == 1 {
			j.link(cgroupID, evt, refined[0])

			return true
		}

		j.registry.LinkCgroup(cgroupID, CgroupBinding{
			ContainerID:         evt.ContainerID,
			CgroupPath:          evt.CgroupPath,
			Ambiguous:           true,
			AmbiguousCandidates: candidatesFromMatches(matches),
		})

		j.logger.Info("cgroup-to-vertex join is ambiguous",
			"container_id", evt.ContainerID,
			"candidates", len(matches),
		)

		return true
	}
}

// noMatch handles a miss. Non-final misses just ask for a retry. A
// final miss under an enforcing policy kills the cgroup; otherwise
// the cgroup stays unbound (its egress is reported unattributed).
func (j *CgroupJoiner) noMatch(ctx context.Context, cgroupID uint64, evt CgroupCreateEvent, final bool) bool {
	if !final || ctx.Err() != nil || !j.registry.EnforcementEnabled() {
		return false
	}

	j.killCgroup(evt.CgroupPath)

	j.logger.Warn("buildkit cgroup killed: no authorized session match before deadline",
		"cgroup_id", cgroupID,
		"container_id", evt.ContainerID,
		"cgroup_path", evt.CgroupPath,
	)

	return true
}

func (j *CgroupJoiner) link(cgroupID uint64, evt CgroupCreateEvent, m PendingVertex) {
	j.registry.LinkCgroup(cgroupID, CgroupBinding{
		SessionRef:    m.SessionRef,
		VertexDigest:  m.VertexDigest,
		VertexName:    m.VertexName,
		ContainerID:   evt.ContainerID,
		CgroupPath:    evt.CgroupPath,
		FrontendAttrs: m.FrontendAttrs,
	})
}

// killMatched kills the cgroup and logs why. The vertex name is
// Dockerfile text and may carry secrets, so only the digest and a
// short hash of the name are logged.
func (j *CgroupJoiner) killMatched(cgroupID uint64, evt CgroupCreateEvent, m PendingVertex, msg string, candidates int) {
	j.killCgroup(evt.CgroupPath)

	attrs := []any{
		"cgroup_id", cgroupID,
		"container_id", evt.ContainerID,
		"cgroup_path", evt.CgroupPath,
		"session_ref", m.SessionRef,
		"vertex_digest", m.VertexDigest,
		"vertex_name_hash", vertexNameHash(m.VertexName),
	}
	if candidates > 0 {
		attrs = append(attrs, "candidates", candidates)
	}

	j.logger.Warn(msg, attrs...)
}

// vertexNameHash returns a short stable hash of a vertex name, enough
// to correlate log lines without recording Dockerfile text.
func vertexNameHash(name string) string {
	sum := sha256.Sum256([]byte(name))

	return hex.EncodeToString(sum[:6])
}

func anyPlaceholder(ms []PendingVertex) bool {
	for i := range ms {
		if ms[i].Placeholder {
			return true
		}
	}

	return false
}

// deferredMatch retries tryMatch on a ticker until it succeeds, the
// deadline expires, or ctx is cancelled. Covers the BuildKit + runc
// timing window where the cgroup directory is created before the
// child PID is in procs AND before the Status stream announces the
// vertex. One goroutine per cgroup create; bounded by buildkit's
// max-parallelism (typically low tens). The attempt at or after the
// deadline is the final one (see tryMatch).
func (j *CgroupJoiner) deferredMatch(ctx context.Context, cgroupID uint64, evt CgroupCreateEvent) {
	deadline := time.Now().Add(j.deferredMatchTimeout)

	tick := time.NewTicker(j.deferredMatchInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		final := !time.Now().Before(deadline)

		if j.tryMatch(ctx, cgroupID, evt, final) {
			return
		}

		if final {
			j.logger.Debug("cgroup-to-vertex join deadline; dropped",
				"container_id", evt.ContainerID,
				"cgroup_id", cgroupID,
				"path", evt.CgroupPath,
			)

			return
		}
	}
}

func (j *CgroupJoiner) handleRemove(evt CgroupRemoveEvent) {
	// First, cancel any in-flight deferred match for this container
	// and wait for it to exit. Without this, a goroutine that wins
	// its retry race AFTER we walk the index below would resurrect a
	// binding for a runc container that's already gone — the remove
	// event would never fire again, so the stale binding would
	// persist until process exit.
	if v, ok := j.inflight.LoadAndDelete(evt.ContainerID); ok {
		pending := v.(*pendingDeferredMatch)
		pending.cancel()
		<-pending.done
	}

	// Resolve the cgroup id by walking the index — the path's
	// inode is already gone by the time the remove event fires,
	// so a fresh stat would either fail or return a recycled
	// inode (rare but possible). Scanning by ContainerID is O(n)
	// over the index, which is bounded by max-parallelism.
	j.registry.mu.Lock()
	defer j.registry.mu.Unlock()

	for id, binding := range j.registry.cgroupIndex {
		if binding.ContainerID == evt.ContainerID {
			delete(j.registry.cgroupIndex, id)

			return
		}
	}
}

// readFirstPID reads cgroupPath/cgroup.procs and returns the first
// PID. Empty cgroups (no processes yet) return os.ErrProcessDone-
// style errors via the underlying read.
func readFirstPID(cgroupPath string) (int, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return 0, fmt.Errorf("read cgroup.procs: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		pid, err := strconv.Atoi(line)
		if err != nil {
			return 0, fmt.Errorf("parse pid %q: %w", line, err)
		}

		return pid, nil
	}

	return 0, errors.New("cgroup.procs is empty")
}

// readArgv returns /proc/<pid>/cmdline split into its argv elements.
func readArgv(procRoot string, pid int) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, fmt.Errorf("read cmdline: %w", err)
	}

	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return nil, errors.New("empty cmdline")
	}

	return strings.Split(trimmed, "\x00"), nil
}

// readEnviron returns /proc/<pid>/environ as a map[KEY]VALUE.
// Unreadable environ (perm denied on systemd-like setups, or pid
// exited) returns an empty map without an error — callers treat it
// as "no tiebreaker available".
func readEnviron(procRoot string, pid int) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil, fmt.Errorf("read environ: %w", err)
	}

	out := make(map[string]string)

	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}

		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}

		out[kv[:eq]] = kv[eq+1:]
	}

	return out, nil
}

// matchPendingByArgv returns the pending vertices whose RUN command
// is exactly the command the process was started with. BuildKit names
// look like:
//
//	"[build 5/12] RUN npm ci"
//	"[stage-final 2/4] COPY --from=build /out /"
//
// Only "RUN" vertices match — COPY/FROM/ARG don't spawn runc
// containers and therefore don't surface as cgroup creates.
//
// BuildKit runs shell-form RUN as `<shell> [opts] -c "<cmd>"`; the
// command string is argv's last element. Equality is on the whole
// (whitespace-normalised) command — a substring test would let any
// process whose command line merely contains another session's RUN
// text inherit that session's authorization.
func matchPendingByArgv(pending []PendingVertex, argv []string) []PendingVertex {
	var out []PendingVertex

	for _, v := range pending {
		cmd := extractRunCommand(v.VertexName)
		if cmd == "" {
			continue
		}

		if argvMatchesRun(argv, cmd) {
			out = append(out, v)
		}
	}

	return out
}

// argvMatchesRun reports whether argv is the invocation of runCmd:
// either `... -c <runCmd>` (shell form) or argv joined == runCmd
// (exec form).
func argvMatchesRun(argv []string, runCmd string) bool {
	want := normalizeWS(runCmd)
	if want == "" || len(argv) == 0 {
		return false
	}

	if n := len(argv); n >= 3 && argv[n-2] == "-c" {
		return normalizeWS(argv[n-1]) == want
	}

	return normalizeWS(strings.Join(argv, " ")) == want
}

func normalizeWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// extractRunCommand returns the command portion of a BuildKit RUN
// vertex name with the bracketed stage prefix and any leading RUN
// flags (--mount=..., --network=..., --security=...) removed.
// Returns "" for non-RUN vertices.
func extractRunCommand(vertexName string) string {
	// Drop the bracketed prefix if present: "[stage 1/2] RUN ..."
	rest := vertexName
	if i := strings.IndexByte(rest, ']'); i > 0 && strings.HasPrefix(rest, "[") {
		rest = strings.TrimLeft(rest[i+1:], " ")
	}

	const runPrefix = "RUN "
	if !strings.HasPrefix(rest, runPrefix) {
		return ""
	}

	rest = strings.TrimSpace(rest[len(runPrefix):])

	for strings.HasPrefix(rest, "--") {
		_, after, found := strings.Cut(rest, " ")
		if !found {
			return ""
		}

		rest = strings.TrimLeft(after, " ")
	}

	return rest
}

// tiebreakByEnviron narrows a multi-match set to candidates whose
// FrontendAttrs values appear in the process environment. Each
// FrontendAttrs entry (e.g. build-arg: KEY=VALUE) is checked against
// /proc/<pid>/environ; a candidate survives if all its attrs match.
// When no candidate has FrontendAttrs, all candidates survive
// (degraded — caller treats the result as still-ambiguous).
func tiebreakByEnviron(matches []PendingVertex, environ map[string]string) []PendingVertex {
	if len(environ) == 0 {
		return matches
	}

	var refined []PendingVertex

	for _, m := range matches {
		if len(m.FrontendAttrs) == 0 {
			refined = append(refined, m)

			continue
		}

		allMatch := true

		for k, want := range m.FrontendAttrs {
			// FrontendAttrs keys include things like
			// "build-arg:FOO" — strip the "build-arg:" prefix to
			// get the env-var name BuildKit injected.
			envKey := strings.TrimPrefix(k, "build-arg:")

			got, ok := environ[envKey]
			if !ok || got != want {
				allMatch = false

				break
			}
		}

		if allMatch {
			refined = append(refined, m)
		}
	}

	if len(refined) == 0 {
		// All candidates had FrontendAttrs and none matched —
		// treat as if no tiebreaker was available.
		return matches
	}

	return refined
}

func candidatesFromMatches(matches []PendingVertex) []AmbiguousCandidate {
	out := make([]AmbiguousCandidate, 0, len(matches))
	for _, m := range matches {
		out = append(out, AmbiguousCandidate{
			SessionRef:   m.SessionRef,
			VertexDigest: m.VertexDigest,
			VertexName:   m.VertexName,
		})
	}

	return out
}

// killCgroup SIGKILLs every process in the given cgroup directory by
// writing "1" to its cgroup.kill file (cgroup v2). Used by the
// kill-switch path when the cgroup is linked to an Unauthorized
// session. Errors are logged at warn level but not propagated — a
// missing cgroup.kill (cgroup v1, or a transient cgroup that was
// removed between detection and kill) is a no-op; nothing we'd want
// to retry.
//
// The cgroup.kill primitive is a single-write atomic operation: the
// kernel signals every process in the cgroup AND every descendant
// cgroup. No race with runc tearing down children; no leftover
// processes. Requires write permission on the cgroup file (agent
// runs as root → fine).
func (j *CgroupJoiner) killCgroup(cgroupPath string) {
	const killFile = "cgroup.kill"

	err := os.WriteFile(filepath.Join(cgroupPath, killFile), []byte("1"), 0)
	if err != nil {
		j.logger.Warn("cgroup.kill write failed",
			"path", cgroupPath,
			"error", err,
		)
	}
}
