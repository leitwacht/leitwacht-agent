package enforcer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

	// killOnUnattributed is the explicit opt-in to the fail-closed kill
	// switch: with require-CI-metadata or deny patterns configured, a
	// cgroup that cannot be attributed (or whose candidates are
	// unauthorized or denied) is SIGKILLed. Off by default: the join
	// layer then only flags the cgroup (CgroupBinding.Flag, surfaced as
	// Violation.BuildFlag) and leaves it running in audit. Unattributable
	// or ambiguous builds must never fail closed unless the operator
	// asked for it.
	killOnUnattributed bool

	// gone marks containers whose cgroup was removed while their match
	// was still pending: a late link for one goes straight to the retired
	// cache (atomically), never through a live index entry.
	gone sync.Map

	// Rate limiting for the join-deadline warning (see logDeadlineDrop).
	dropMu         sync.Mutex
	lastDropLog    time.Time
	dropSuppressed int
}

// pendingDeferredMatch is the handle on one in-flight deferred-match
// goroutine. cancel signals the goroutine to give up; done closes
// when the goroutine returns.
type pendingDeferredMatch struct {
	cancel context.CancelFunc
	done   chan struct{}

	// removed is closed when the cgroup's remove event arrives while the
	// match is still pending. The goroutine then makes one last attempt
	// with the argv it captured while the process was alive, so a RUN
	// step that finishes before it could be matched is still linked
	// (its binding is retired, not live, by handleRemove).
	removed     chan struct{}
	removedOnce sync.Once
}

func (p *pendingDeferredMatch) signalRemoved() { p.removedOnce.Do(func() { close(p.removed) }) }

// matchState carries what a join attempt learned about one cgroup across
// retries: its argv (read while the process was alive; a fast RUN step
// can exit, emptying cgroup.procs, before the next attempt) and when the
// cgroup appeared (to select vertices that were running then).
type matchState struct {
	at   time.Time
	gone bool // the cgroup was removed while the match was pending

	// goodPID/goodArgv are the latest argv that is not an init helper.
	goodPID  int
	goodArgv []string
}

// isInitArgv reports whether argv is a container-runtime helper (runc's
// init, a buildkit runc wrapper) rather than the RUN step's own process.
func isInitArgv(argv []string) bool {
	if len(argv) == 0 {
		return true
	}

	base := filepath.Base(argv[0])
	// Exact basenames: a prefix match would also swallow user binaries
	// such as runcmd or runctl.
	if base == "runc" || base == "buildkit-runc" {
		return true
	}

	return argv[0] == "/proc/self/exe" && len(argv) > 1 && argv[1] == "init"
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

// WithKillOnUnattributed opts in to the fail-closed kill switch (see
// CgroupJoiner.killOnUnattributed). Default off: unattributable cgroups
// are flagged and audited, not killed.
func WithKillOnUnattributed(enabled bool) JoinerOption {
	return func(j *CgroupJoiner) { j.killOnUnattributed = enabled }
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
		deferredMatchInterval: 25 * time.Millisecond,
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
	sourceDone := make(chan struct{})

	go func() {
		defer close(sourceDone)

		sourceErr <- j.source.Run(ctx, creates, removes)
	}()

	// Await the source goroutine so a caller that cancels ctx and
	// waits for Run knows the event source is gone. (Deferred-match
	// goroutines are bound to ctx and exit on cancellation; they are
	// not awaited here.)
	defer func() {
		<-sourceDone
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

	// A rescan (queue overflow, re-watch) re-reports cgroups that are
	// already bound; do not re-judge a linked RUN.
	if j.registry.hasBindingForPath(cgroupID, evt.CgroupPath) {
		return
	}

	// First attempt runs synchronously so the happy fast-path
	// (cgroup already populated, vertex already announced) takes
	// no goroutine. The deferred loop only spawns when this misses.
	st := &matchState{at: time.Now()}

	if j.tryMatchState(ctx, cgroupID, evt, j.deferredMatchTimeout <= 0, st) {
		return
	}

	if j.deferredMatchTimeout <= 0 {
		// No retry window: the single attempt above was final. Egress
		// events for this cgroup will be emitted unattributed.
		j.registry.noteJoinOutcome(cgroupID, evt.CgroupPath, JoinDeadline)

		return
	}

	// Register an inflight entry so a concurrent handleRemove for
	// this ContainerID can cancel the goroutine and wait for it to
	// exit before doing its unlink walk.
	pendingCtx, cancel := context.WithCancel(ctx)
	pending := &pendingDeferredMatch{
		cancel:  cancel,
		done:    make(chan struct{}),
		removed: make(chan struct{}),
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
		defer cancel()
		defer close(pending.done)
		defer j.inflight.CompareAndDelete(evt.ContainerID, pending)

		j.deferredMatch(pendingCtx, cgroupID, evt, pending, st)
	}()
}

// Attribution-trust flags raised in place of a kill (Violation.BuildFlag).
const (
	BuildFlagMissingCI     = "missing_ci_attribution"
	BuildFlagDenyPattern   = "deny_pattern_match"
	BuildFlagArgvUntrusted = "argv_untrusted"
	BuildFlagUnmatched     = "unmatched_under_policy"
	// BuildFlagHistoryDisconnected is stamped on rows of cgroups judged
	// while the history watcher was down.
	BuildFlagHistoryDisconnected = "history_disconnected"
)

// candidateKey is the policy key a pending vertex's session claims.
func candidateKey(v PendingVertex) PolicyKey {
	return keyFromAttrs(v.FrontendAttrs)
}

func candidateKeysOf(ms []PendingVertex) []PolicyKey {
	out := make([]PolicyKey, 0, len(ms))
	for _, m := range ms {
		out = append(out, candidateKey(m))
	}

	return out
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
	return j.tryMatchState(ctx, cgroupID, evt, final, &matchState{at: time.Now()})
}

func (j *CgroupJoiner) tryMatchState(
	ctx context.Context, cgroupID uint64, evt CgroupCreateEvent, final bool, st *matchState,
) bool {
	// Re-read the first process's argv on every attempt while the cgroup
	// exists: early on it is often runc's init or a shim, and only later
	// the real `sh -c ...`. The last GOOD argv (non-empty, not an init
	// helper) is remembered for fast steps whose process exits before the
	// next attempt, and is the only one used once the cgroup is gone.
	if !st.gone {
		pid, err := readFirstPID(evt.CgroupPath)
		if err == nil {
			var argv []string

			argv, err = readArgv(j.procRoot, pid)
			if err == nil {
				if !isInitArgv(argv) {
					st.goodPID, st.goodArgv = pid, argv
				}
			}
		}
	}

	if st.goodArgv == nil {
		return j.noMatch(ctx, cgroupID, evt, final)
	}

	argv, pid := st.goodArgv, st.goodPID

	pending := j.registry.CandidateVertices(st.at)
	matches := matchPendingByArgv(pending, argv)

	// Completed vertices only widen a set. If they are all there is, a
	// single link could pick another session's finished step with the
	// same text (the real owner's vertex not announced yet), so unless
	// that is provably safe the cgroup stays unbound.
	if len(matches) > 0 && allCompleted(matches) && !j.completedOnlySafe(matches, st.at) {
		return j.noMatch(ctx, cgroupID, evt, final)
	}

	if len(matches) == 0 {
		if weak := matchPendingByTail(pending, argv); len(weak) > 0 {
			return j.tryWeakMatch(ctx, cgroupID, evt, weak, final)
		}
	}

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
		flag := ""

		if !m.Authorized {
			if j.killOnUnattributed {
				j.killMatched(cgroupID, evt, m, "buildkit cgroup killed: session missing required CI attribution", 0)

				return true
			}

			flag = BuildFlagMissingCI
		}

		// Per-vertex kill-switch: server policy can install regex
		// patterns matching vertex_name (e.g. "RUN npm install"). A
		// match SIGKILLs the cgroup, same mechanism as the missing-
		// CI-metadata path above. Skipped when no patterns are
		// installed — back-compat for installations that haven't
		// opted into per-vertex policy.
		//
		// A definite match on a single exactly-linked vertex is explicit
		// operator policy, not a fail-closed guess: it kills regardless of
		// WithKillOnUnattributed (which only gates the uncertain paths).
		if j.registry.MatchesDenyVertexPattern(m.VertexName) {
			j.killMatched(cgroupID, evt, m, "buildkit cgroup killed: vertex matched a deny policy pattern", 0)

			return true
		}

		stop, untrusted := j.distrustArgvMatch(cgroupID, evt, 1)
		if stop {
			return true
		}

		if untrusted && flag == "" {
			flag = BuildFlagArgvUntrusted
		}

		j.linkWith(cgroupID, evt, m, StrengthExactArgv, []PolicyKey{candidateKey(m)}, flag)

		j.logger.Info("buildkit cgroup linked",
			"cgroup_id", cgroupID,
			"container_id", evt.ContainerID,
			"session_ref", m.SessionRef,
			"vertex_digest", m.VertexDigest,
			"vertex_name_hash", VertexNameHash(m.VertexName),
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
		ambFlag := ""

		for i := range matches {
			if !matches[i].Authorized {
				if j.killOnUnattributed {
					j.killMatched(cgroupID, evt, matches[i], "buildkit cgroup killed: ambiguous candidate missing required CI attribution", len(matches))

					return true
				}

				if ambFlag == "" {
					ambFlag = BuildFlagMissingCI
				}
			}

			if j.registry.MatchesDenyVertexPattern(matches[i].VertexName) {
				if j.killOnUnattributed {
					j.killMatched(cgroupID, evt, matches[i], "buildkit cgroup killed: ambiguous candidate matched a deny policy pattern", len(matches))

					return true
				}

				if ambFlag == "" {
					ambFlag = BuildFlagDenyPattern
				}
			}
		}

		stop, untrusted := j.distrustArgvMatch(cgroupID, evt, len(matches))
		if stop {
			return true
		}

		if untrusted && ambFlag == "" {
			ambFlag = BuildFlagArgvUntrusted
		}

		// Tiebreaker: environ. Read /proc/<pid>/environ and pick
		// the candidate whose FrontendAttrs values appear in the
		// process environment. Falls through to ambiguous if the
		// tiebreaker also yields >1 (or 0 — the more likely case
		// when neither side's attrs surface in env).
		environ, _ := readEnviron(j.procRoot, pid)

		refined := tiebreakByEnviron(matches, environ)
		if len(refined) == 1 {
			// Row attribution follows the tiebreak, but the policy binder
			// sees every candidate: environ is forgeable, so it never
			// chooses between projects.
			j.linkWith(cgroupID, evt, refined[0], StrengthEnvironTiebreak, candidateKeysOf(matches), ambFlag)

			return true
		}

		j.linkCgroup(cgroupID, CgroupBinding{
			ContainerID:         evt.ContainerID,
			CgroupPath:          evt.CgroupPath,
			Ambiguous:           true,
			AmbiguousCandidates: candidatesFromMatches(matches),
			Strength:            StrengthAmbiguous,
			CandidateKeys:       candidateKeysOf(matches),
			Flag:                ambFlag,
		})

		j.logger.Info("cgroup-to-vertex join is ambiguous",
			"container_id", evt.ContainerID,
			"candidates", len(matches),
		)

		return true
	}
}

// tryWeakMatch handles candidates found only through the last-simple-
// command tier. That evidence is forgeable (argv and environ are both
// controlled by the RUN), so it is never single-linked: the cgroup is
// bound ambiguous over the weak candidates, or treated as unmatched
// under a policy.
func (j *CgroupJoiner) tryWeakMatch(ctx context.Context, cgroupID uint64, evt CgroupCreateEvent, weak []PendingVertex, final bool) bool {
	if !final {
		return false
	}

	if ctx.Err() != nil {
		return true
	}

	if j.killOnUnattributed && j.registry.EnforcementEnabled() {
		return j.noMatch(ctx, cgroupID, evt, true)
	}

	j.linkCgroup(cgroupID, CgroupBinding{
		ContainerID:         evt.ContainerID,
		CgroupPath:          evt.CgroupPath,
		Ambiguous:           true,
		AmbiguousCandidates: candidatesFromMatches(weak),
		Strength:            StrengthWeakTail,
		CandidateKeys:       candidateKeysOf(weak),
	})

	j.logger.Info("cgroup-to-vertex join is ambiguous (last-command match only)",
		"container_id", evt.ContainerID,
		"candidates", len(weak),
	)

	return true
}

// distrustArgvMatch implements the fail-closed rule for argv-derived
// matches: argv is controlled by the process (exec -a, setproctitle), so
// a match proves nothing about which session owns the cgroup. Under a
// policy, while any unauthorized, placeholder or deny-matching session
// is open, no match is trusted. With the kill opt-in the cgroup is
// killed instead of bound (forging argv must not dodge the kill);
// returns stop=true then. With kill off the match is only flagged
// (argv_untrusted, for anomaly review) and the binder still applies the
// matched key's policy: a forger's own steps are unattributed and run in
// audit with unrestricted egress anyway, so being judged by another
// build's policy is never looser than that audit default (equal when the
// matched key itself runs in audit), whereas downgrading to audit would switch off
// enforcement for every concurrent build.
func (j *CgroupJoiner) distrustArgvMatch(cgroupID uint64, evt CgroupCreateEvent, candidates int) (stop, untrusted bool) {
	if !j.registry.EnforcementEnabled() || !j.registry.PolicyCandidates().Risky {
		return false, false
	}

	if !j.killOnUnattributed {
		// Flag, do not kill: the match is still used for attribution and
		// binding (the binder classifies by candidate keys regardless of
		// the flag), and the row carries argv_untrusted for review.
		return false, true
	}

	if j.killCgroup(evt.CgroupPath) {
		j.logger.Warn("buildkit cgroup killed: argv match not trusted while an unauthorized or denied session is open",
			"cgroup_id", cgroupID,
			"container_id", evt.ContainerID,
			"cgroup_path", evt.CgroupPath,
			"candidates", candidates,
		)
	}

	return true, true
}

// noMatch handles a miss. Non-final misses just ask for a retry. A
// final miss under a configured policy is treated cautiously: the
// cgroup may be a legitimate container the vertex text cannot be
// matched to (a "# syntax=" frontend container, or a RUN whose command
// BuildKit renders differently from what runs). The candidate set is
// every pending RUN vertex of every open session. By default the cgroup
// is never killed: if the history watcher is down it is reported to the
// policy binder as degraded_history; if an open session is unauthorized,
// still a placeholder, or a pending vertex matches a deny pattern, the
// cgroup is bound ambiguous over all candidates with the
// unmatched_under_policy flag. With the explicit kill opt-in
// (WithKillOnUnattributed) those risky cases kill the cgroup, as before.
// Without a policy a miss just leaves the cgroup unbound.
func (j *CgroupJoiner) noMatch(ctx context.Context, cgroupID uint64, evt CgroupCreateEvent, final bool) bool {
	if !final || ctx.Err() != nil || !j.registry.EnforcementEnabled() {
		return false
	}

	pc := j.registry.PolicyCandidates()
	historyDown := j.registry.HistoryDisconnected()

	if (historyDown || pc.Risky) && j.killOnUnattributed {
		reason := "buildkit cgroup killed: unmatched under policy with unauthorized or denied candidate sessions"
		if historyDown {
			reason = "buildkit cgroup killed: unmatched while the history watcher is disconnected"
		}

		if j.killCgroup(evt.CgroupPath) {
			j.logger.Warn(reason,
				"cgroup_id", cgroupID,
				"container_id", evt.ContainerID,
				"cgroup_path", evt.CgroupPath,
				"candidates", len(pc.Vertices),
			)
		}

		return true
	}

	if historyDown {
		// The registry is blind to new sessions: any candidate set would
		// be a guess. Leave the cgroup unbound and tell the binder.
		j.logger.Warn("buildkit cgroup unmatched while the history watcher is disconnected; running in audit",
			"cgroup_id", cgroupID,
			"container_id", evt.ContainerID,
		)

		j.registry.noteJoinOutcome(cgroupID, evt.CgroupPath, JoinHistoryDown)

		return true
	}

	if len(pc.Vertices) > 0 {
		flag := ""
		if pc.Risky {
			flag = BuildFlagUnmatched
		}

		j.linkCgroup(cgroupID, CgroupBinding{
			ContainerID:         evt.ContainerID,
			CgroupPath:          evt.CgroupPath,
			Ambiguous:           true,
			AmbiguousCandidates: candidatesFromMatches(pc.Vertices),
			Strength:            StrengthSessionLevel,
			CandidateKeys:       candidateKeysOf(pc.Vertices),
			Flag:                flag,
		})

		j.logger.Info("cgroup unmatched under policy; bound ambiguous over all open sessions",
			"container_id", evt.ContainerID,
			"candidates", len(pc.Vertices),
		)

		return true
	}

	j.registry.noteJoinOutcome(cgroupID, evt.CgroupPath, JoinDeadline)

	return true
}

// linkCgroup records a binding: live, or straight into the retired cache
// when the container's cgroup is already gone.
func (j *CgroupJoiner) linkCgroup(cgroupID uint64, b CgroupBinding) {
	if _, gone := j.gone.Load(b.ContainerID); gone {
		j.registry.linkCgroupRetired(cgroupID, b)

		return
	}

	j.registry.LinkCgroup(cgroupID, b)
}

func (j *CgroupJoiner) link(cgroupID uint64, evt CgroupCreateEvent, m PendingVertex) {
	j.linkWith(cgroupID, evt, m, StrengthExactArgv, []PolicyKey{candidateKey(m)}, "")
}

func (j *CgroupJoiner) linkWith(
	cgroupID uint64, evt CgroupCreateEvent, m PendingVertex, strength string, keys []PolicyKey, flag string,
) {
	j.linkCgroup(cgroupID, CgroupBinding{
		SessionRef:    m.SessionRef,
		VertexDigest:  m.VertexDigest,
		VertexName:    m.VertexName,
		ContainerID:   evt.ContainerID,
		CgroupPath:    evt.CgroupPath,
		FrontendAttrs: m.FrontendAttrs,
		Strength:      strength,
		CandidateKeys: keys,
		Flag:          flag,
	})
}

// killMatched kills the cgroup and logs why. The vertex name is
// Dockerfile text and may carry secrets, so only the digest and a
// short hash of the name are logged.
func (j *CgroupJoiner) killMatched(cgroupID uint64, evt CgroupCreateEvent, m PendingVertex, msg string, candidates int) {
	if !j.killCgroup(evt.CgroupPath) {
		return
	}

	attrs := []any{
		"cgroup_id", cgroupID,
		"container_id", evt.ContainerID,
		"cgroup_path", evt.CgroupPath,
		"session_ref", m.SessionRef,
		"vertex_digest", m.VertexDigest,
		"vertex_name_hash", VertexNameHash(m.VertexName),
	}
	if candidates > 0 {
		attrs = append(attrs, "candidates", candidates)
	}

	j.logger.Warn(msg, attrs...)
}

// VertexNameHash returns a short stable hash of a vertex name, enough
// to correlate log lines without recording Dockerfile text.
func VertexNameHash(name string) string {
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
func (j *CgroupJoiner) deferredMatch(
	ctx context.Context, cgroupID uint64, evt CgroupCreateEvent, pending *pendingDeferredMatch, st *matchState,
) {
	deadline := time.Now().Add(j.deferredMatchTimeout)

	tick := time.NewTicker(j.deferredMatchInterval)
	defer tick.Stop()

	removedCh := pending.removed

	for {
		select {
		case <-ctx.Done():
			return
		case <-removedCh:
			// The cgroup is gone. Without a captured argv nothing can
			// ever match. With one, keep matching (the vertex may be
			// announced after the step already finished) until the
			// deadline; a late link is retired immediately below, never
			// left live for a cgroup that no longer exists.
			removedCh = nil

			if st.goodArgv == nil {
				return
			}

			st.gone = true
			j.gone.Store(evt.ContainerID, true)
		case <-tick.C:
		}

		final := !time.Now().Before(deadline)

		if j.tryMatchState(ctx, cgroupID, evt, final, st) {
			if st.gone {
				j.registry.retireContainer(cgroupID, evt.ContainerID) // the cgroup no longer exists
				j.gone.Delete(evt.ContainerID)
			}

			return
		}

		if final {
			j.logDeadlineDrop(cgroupID, evt)
			j.registry.noteJoinOutcome(cgroupID, evt.CgroupPath, JoinDeadline)

			return
		}
	}
}

// dropLogInterval rate-limits the join-deadline warning: a burst of
// unmatched RUN containers logs once per interval with a suppressed count.
const dropLogInterval = 10 * time.Second

// logDeadlineDrop reports a RUN cgroup left unattributed because no
// pending vertex matched before the join deadline. Its egress is
// reported without build attribution, so this must not be silent.
func (j *CgroupJoiner) logDeadlineDrop(cgroupID uint64, evt CgroupCreateEvent) {
	j.dropMu.Lock()

	now := time.Now()
	if !j.lastDropLog.IsZero() && now.Sub(j.lastDropLog) < dropLogInterval {
		j.dropSuppressed++
		j.dropMu.Unlock()

		return
	}

	suppressed := j.dropSuppressed
	j.dropSuppressed = 0
	j.lastDropLog = now
	j.dropMu.Unlock()

	j.logger.Warn("buildkit cgroup not attributed: no pending vertex matched before the join deadline",
		"container_id", evt.ContainerID,
		"cgroup_id", cgroupID,
		"path", evt.CgroupPath,
		"pending_vertices", len(j.registry.PendingVertices()),
		"history_disconnected", j.registry.HistoryDisconnected(),
		"suppressed_since_last", suppressed,
	)
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
		// Do not wait: a pending match with a captured argv keeps going
		// after removal and retires its own binding (see deferredMatch).
		pending.signalRemoved()
	}

	// Resolve the cgroup id by walking the index — the path's
	// inode is already gone by the time the remove event fires,
	// so a fresh stat would either fail or return a recycled
	// inode (rare but possible). Scanning by ContainerID is O(n)
	// over the index, which is bounded by max-parallelism.
	j.registry.mu.Lock()

	var (
		goneID uint64
		found  bool
	)

	for id, binding := range j.registry.cgroupIndex {
		if binding.ContainerID == evt.ContainerID {
			j.registry.retireLocked(id, binding)
			delete(j.registry.cgroupIndex, id)

			goneID, found = id, true

			break
		}
	}

	j.registry.mu.Unlock()

	if found {
		if ob := j.registry.obs(); ob != nil {
			ob.OnUnbind(goneID)
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

		if argvMatchesRun(argv, cmd) || argvMatchesRunLoose(argv, cmd) {
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

// argvMatchesRunLoose widens argvMatchesRun for the legitimate forms
// where the vertex text and the process argv differ. Every widening can
// only over-match; over-matching yields an ambiguous candidate set,
// which the policy checks treat fail-closed.
func argvMatchesRunLoose(argv []string, runCmd string) bool {
	if len(argv) == 0 {
		return false
	}

	// Exec form: the vertex name carries a JSON array, compare
	// element-wise.
	if strings.HasPrefix(runCmd, "[") {
		var elems []string
		if json.Unmarshal([]byte(runCmd), &elems) == nil && len(elems) > 0 {
			return execFormMatches(argv, elems)
		}
	}

	// Heredoc: "<<EOF ..." summary versus the first line of the script.
	if strings.HasPrefix(runCmd, "<<") {
		return heredocMatches(argv[len(argv)-1], runCmd)
	}

	script := argv[len(argv)-1]
	hasShellC := len(argv) >= 3 && argv[len(argv)-2] == "-c"

	// $VAR / ${VAR} in the script are expanded in the vertex name.
	if hasShellC && strings.Contains(script, "$") && varPatternMatches(script, runCmd) {
		return true
	}

	// The shell exec-replaced itself with the last simple command, so
	// argv is the resolved command, possibly behind an interpreter
	// (pip install x -> python3 /usr/local/bin/pip install x).
	return tailMatchesCommand(argv, runCmd)
}

func allCompleted(ms []PendingVertex) bool {
	for i := range ms {
		if !ms[i].Completed {
			return false
		}
	}

	return len(ms) > 0
}

// completedOnlySafe reports whether a match set made only of completed
// vertices may be linked: exactly one candidate, and the registry knows
// of exactly one session active at that time (reliably), so no other
// session can own the cgroup.
func (j *CgroupJoiner) completedOnlySafe(ms []PendingVertex, at time.Time) bool {
	if len(ms) != 1 {
		return false
	}

	// One RUN vertex maps to one runc container: if this vertex already
	// has a cgroup (live or recently retired), a second cgroup cannot be
	// its step.
	if j.registry.vertexHasCgroup(ms[0].SessionRef, ms[0].VertexDigest) {
		return false
	}

	sessions, reliable := j.registry.SessionsActiveAt(at)

	return reliable && len(sessions) == 1 && sessions[0].Ref == ms[0].SessionRef
}

// matchPendingByTail is the weakest tier: it matches only the last
// simple command of a compound RUN (see lastSimpleCommandMatches). Used
// only when matchPendingByArgv found nothing, and never trusted on its
// own: a short common command (`make`, `sleep 3`) is easy to guess, so a
// process can shape its argv to claim another session's RUN.
func matchPendingByTail(pending []PendingVertex, argv []string) []PendingVertex {
	var out []PendingVertex

	for _, v := range pending {
		cmd := extractRunCommand(v.VertexName)
		if cmd != "" && lastSimpleCommandMatches(argv, cmd) {
			out = append(out, v)
		}
	}

	return out
}

func execFormMatches(argv, elems []string) bool {
	if len(argv) == len(elems) {
		eq := true

		for i := range elems {
			if argv[i] != elems[i] {
				eq = false

				break
			}
		}

		if eq {
			return true
		}
	}

	// Resolved binary path / interpreter prefix.
	n := len(elems)
	if len(argv) < n {
		return false
	}

	off := len(argv) - n
	if path.Base(argv[off]) != path.Base(elems[0]) {
		return false
	}

	for i := 1; i < n; i++ {
		if argv[off+i] != elems[i] {
			return false
		}
	}

	return true
}

var heredocTagRE = regexp.MustCompile(`^<<-?\s*["']?[A-Za-z_][A-Za-z0-9_]*["']?\s*`)

// heredocMatches compares the heredoc summary in the vertex name (the
// script's first line, wrapped in parentheses) with the script's first line. Equality is required;
// a prefix is accepted only when the summary was truncated with "...".
// A bare "<<EOF" with no summary matches nothing.
func heredocMatches(script, runCmd string) bool {
	head := firstNonEmptyLine(heredocTagRE.ReplaceAllString(runCmd, ""))
	// BuildKit renders the summary as "<<EOF (<first line>...)".
	if strings.HasPrefix(head, "(") && strings.HasSuffix(head, ")") {
		head = strings.TrimSpace(head[1 : len(head)-1])
	}

	truncated := strings.HasSuffix(head, "...")
	head = strings.TrimSpace(strings.TrimSuffix(head, "..."))

	first := firstNonEmptyLine(script)

	if head == "" || first == "" {
		return false
	}

	return head == first || (truncated && strings.HasPrefix(first, head))
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := normalizeWS(line); l != "" {
			return l
		}
	}

	return ""
}

var shellVarRE = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

const maxVarPatternLen = 4096

// varPatternMatches reports whether runCmd (the vertex text, variables
// already expanded) fits script with each $X/${X} as a non-greedy
// wildcard, anchored at both ends on whitespace-normalised text.
func varPatternMatches(script, runCmd string) bool {
	script = normalizeWS(script)
	if len(script) > maxVarPatternLen || !shellVarRE.MatchString(script) {
		return false
	}

	var sb strings.Builder

	sb.WriteString("^")

	last := 0
	for _, loc := range shellVarRE.FindAllStringIndex(script, -1) {
		sb.WriteString(regexp.QuoteMeta(script[last:loc[0]]))
		sb.WriteString(".*?")

		last = loc[1]
	}

	sb.WriteString(regexp.QuoteMeta(script[last:]))
	sb.WriteString("$")

	re, err := regexp.Compile(sb.String())
	if err != nil {
		return false
	}

	return re.MatchString(normalizeWS(runCmd))
}

// tailMatchesCommand matches a simple command (no shell operators)
// against the last len(tokens) argv elements, comparing the program by
// base name.
func tailMatchesCommand(argv []string, runCmd string) bool {
	if strings.ContainsAny(runCmd, ";&|<>()$`\n") {
		return false
	}

	tokens := strings.Fields(runCmd)

	n := len(tokens)
	if n == 0 || len(argv) < n {
		return false
	}

	off := len(argv) - n
	if strings.ContainsAny(argv[off], " \t\n") || path.Base(argv[off]) != path.Base(tokens[0]) {
		return false
	}

	for i := 1; i < n; i++ {
		if argv[off+i] != tokens[i] {
			return false
		}
	}

	return true
}

// lastSimpleCommandMatches matches argv against the final simple command
// of a compound RUN (`a && (b; c) && d`). The shell exec-replaces itself
// with that command, so a process sampled after the earlier steps ran
// shows only its argv. The whole line must be free of anything the
// shell would expand or re-parse ($, backticks, globs, braces, comments,
// heredocs); otherwise it is not matched.
func lastSimpleCommandMatches(argv []string, runCmd string) bool {
	last, ok := lastSimpleCommand(runCmd)
	if !ok || len(last) == 0 || len(argv) < len(last) {
		return false
	}

	off := len(argv) - len(last)
	if strings.ContainsAny(argv[off], " \t\n") || path.Base(argv[off]) != path.Base(last[0]) {
		return false
	}

	for i := 1; i < len(last); i++ {
		if argv[off+i] != last[i] {
			return false
		}
	}

	return true
}

// lastSimpleCommand returns the words of the last top-level simple
// command of a shell command line, with quotes removed and unquoted
// redirections dropped. ok is false when the line is not simple enough to
// tokenise safely (expansions, comments, heredocs, glued redirections).
//
//nolint:gocognit,cyclop,funlen // single-pass shell tokenizer; splitting it hurts readability
func lastSimpleCommand(line string) ([]string, bool) {
	type word struct {
		text   string
		quoted bool
	}

	var (
		words   []word
		cur     strings.Builder
		inWord  bool
		wordQ   bool
		quote   rune
		depth   int
		escaped bool
	)

	endWord := func() {
		if inWord {
			words = append(words, word{cur.String(), wordQ})
			cur.Reset()

			inWord, wordQ = false, false
		}
	}

	reset := func() {
		words, inWord, wordQ = nil, false, false

		cur.Reset()
	}

	rs := []rune(line)

	for i, c := range rs {
		switch {
		case escaped:
			cur.WriteRune(c)

			inWord, wordQ = true, true
			escaped = false
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case quote == '"':
			switch c {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			case '$', '`':
				if depth == 0 {
					return nil, false
				}
			default:
				cur.WriteRune(c)
			}
		case c == '\\':
			escaped = true
		case c == '\'' || c == '"':
			quote = c
			inWord, wordQ = true, true
		case c == '(':
			depth++

			reset()
		case c == ')':
			if depth == 0 {
				return nil, false
			}

			depth--

			reset()
		case depth > 0:
			// Inside a subshell: only its closing paren matters.
		case c == '$' || c == '`' || c == '*' || c == '?' || c == '[' || c == '{' || c == '}' || c == '~' || c == '#':
			return nil, false
		case c == '<' && i+1 < len(rs) && rs[i+1] == '<':
			return nil, false
		case (c == '>' || c == '<') && inWord && !wordQ && strings.Trim(cur.String(), "0123456789") != "":
			// `hi>/dev/null`: the redirection is glued to a word.
			return nil, false
		case c == '&' && (i > 0 && (rs[i-1] == '>' || rs[i-1] == '<') || i+1 < len(rs) && rs[i+1] == '>'):
			// Redirection (2>&1, &>f), not a list separator.
			cur.WriteRune(c)

			inWord = true
		case c == '&' || c == '|' || c == ';' || c == '\n':
			endWord()

			words = nil
		case c == ' ' || c == '\t':
			endWord()
		default:
			cur.WriteRune(c)

			inWord = true
		}
	}

	if quote != 0 || escaped || depth != 0 {
		return nil, false
	}

	endWord()

	out := make([]string, 0, len(words))

	for i := 0; i < len(words); i++ {
		w := words[i]
		t := strings.TrimLeft(w.text, "0123456789")

		if !w.quoted && (strings.HasPrefix(t, ">") || strings.HasPrefix(t, "<")) {
			// Bare operator: the target is the next word.
			if strings.Trim(t, "<>") == "" && i+1 < len(words) {
				i++
			}

			continue
		}

		out = append(out, w.text)
	}

	return out, len(out) > 0
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
// TODO: forgeable — a RUN controls its own environ and build-arg values
// are guessable CI metadata; do not treat this as authorization.
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
// to retry. Returns true only when the kill was written.
//
// The cgroup.kill primitive is a single-write atomic operation: the
// kernel signals every process in the cgroup AND every descendant
// cgroup. No race with runc tearing down children; no leftover
// processes. Requires write permission on the cgroup file (agent
// runs as root → fine).
func (j *CgroupJoiner) killCgroup(cgroupPath string) bool {
	const killFile = "cgroup.kill"

	err := os.WriteFile(filepath.Join(cgroupPath, killFile), []byte("1"), 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Cgroup already gone: nothing was killed, nothing to report.
			j.logger.Debug("cgroup.kill skipped: cgroup gone", "path", cgroupPath)

			return false
		}

		j.logger.Warn("cgroup.kill write failed",
			"path", cgroupPath,
			"error", err,
		)

		return false
	}

	return true
}
