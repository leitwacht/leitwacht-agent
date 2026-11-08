package enforcer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Defaults for CgroupResolver. buildkitd creates its cgroup parent
// lazily (on the first RUN step), so on a fresh node the agent usually
// starts before the path exists; the resolver polls at a flat interval
// until it appears and afterwards to pick up additional paths.
const (
	DefaultCgroupPollInterval = 15 * time.Second
	// DefaultCgroupMinRestartInterval is the minimum gap between
	// joiner restarts caused by path-set changes; it doubles on
	// consecutive restarts.
	DefaultCgroupMinRestartInterval = 5 * time.Minute
	// DefaultCgroupAttachRetryMax caps the attach retry backoff.
	DefaultCgroupAttachRetryMax = 5 * time.Minute
	// DefaultCgroupMaxPaths caps the resolved path count.
	DefaultCgroupMaxPaths = 32
	// DefaultCgroupEventSettle coalesces a burst of directory events
	// into a single re-resolve.
	DefaultCgroupEventSettle = 50 * time.Millisecond
	// DefaultCgroupMinAddInterval floors the gap between additive applies.
	DefaultCgroupMinAddInterval = 2 * time.Second
	// maxCgroupWatchDirs caps the directories one resolver watches.
	maxCgroupWatchDirs = 256
)

// CgroupDirWatcher reports, without detail, that something was
// created (or a watched directory went away) under the directories
// last passed to Watch. Events carries a coalescing signal: at most one
// pending notification, never blocking the watcher.
type CgroupDirWatcher interface {
	// Watch makes dirs the watched set: new ones are added, ones no
	// longer listed are dropped. Directories that vanish meanwhile
	// are skipped silently.
	Watch(dirs []string) error
	Events() <-chan struct{}
	Close() error
}

// cgroupWatchDirs returns the existing directories whose child
// creation can change what patterns resolve to: for each pattern, the
// directory holding a glob component, the nearest existing ancestor of
// a missing literal component, and the parent of the final component.
// Directories on the way to currently resolved paths rank first, then
// ones that only await a lazily created literal, each shallow-first;
// the result is capped at limit and truncated reports whether the cap
// dropped anything.
func cgroupWatchDirs(patterns []string, limit int) (dirs []string, truncated bool) {
	const (
		rankResolved = 0 // leads to (or holds) a currently resolved path, or holds a glob
		rankAwaiting = 1 // only waits for a missing literal to appear
	)

	rank := make(map[string]int)
	mark := func(d string, r int) {
		if old, ok := rank[d]; !ok || r < old {
			rank[d] = r
		}
	}

	for _, pat := range patterns {
		pat = filepath.Clean(pat)
		comps := strings.Split(pat, string(filepath.Separator))
		cur := []string{"."}

		if filepath.IsAbs(pat) {
			cur = []string{string(filepath.Separator)}
			comps = comps[1:]
		}

		for i, c := range comps {
			if c == "" {
				continue
			}

			last := i == len(comps)-1
			next := make([]string, 0, len(cur))

			for _, d := range cur {
				if strings.ContainsAny(c, "*?[") {
					mark(d, rankResolved)

					ents, err := os.ReadDir(d)
					if err != nil {
						continue
					}

					for _, e := range ents {
						if ok, merr := filepath.Match(c, e.Name()); merr == nil && ok && e.IsDir() {
							next = append(next, filepath.Join(d, e.Name()))
						}
					}

					continue
				}

				child := filepath.Join(d, c)
				if fi, err := os.Stat(child); err == nil && fi.IsDir() {
					if last {
						mark(d, rankResolved)
					}

					next = append(next, child)
				} else {
					mark(d, rankAwaiting)
				}
			}

			cur = next
			if len(cur) > limit {
				cur = cur[:limit]
			}
		}
	}

	dirs = make([]string, 0, len(rank))
	for d := range rank {
		dirs = append(dirs, d)
	}

	slices.SortFunc(dirs, func(a, b string) int {
		if rank[a] != rank[b] {
			return rank[a] - rank[b]
		}

		if da, db := strings.Count(a, "/"), strings.Count(b, "/"); da != db {
			return da - db
		}

		return strings.Compare(a, b)
	})

	if len(dirs) > limit {
		dirs, truncated = dirs[:limit], true
	}

	return dirs, truncated
}

// Backoff bounds between cgroup-joiner restarts.
const (
	joinerRestartMin = time.Second
	joinerRestartMax = time.Minute
)

// JoinerRunner is the part of the cgroup joiner the supervisor needs;
// an interface so tests can drive restarts.
type JoinerRunner interface {
	Run(ctx context.Context) error
}

// superviseJoiner runs the cgroup joiner and restarts it with
// exponential backoff whenever it exits before ctx is done. A dead
// joiner would otherwise leave every new RUN cgroup unbound (and, with
// a kill policy configured, unchecked) until the agent restarts. It
// returns when ctx is done or the joiner reports
// ErrCgroupJoinUnsupported.
func superviseJoiner(ctx context.Context, joiner JoinerRunner, log *slog.Logger) {
	superviseJoinerWith(ctx, joiner, log, joinerRestartMin, joinerRestartMax)
}

func superviseJoinerWith(ctx context.Context, joiner JoinerRunner, log *slog.Logger, minB, maxB time.Duration) {
	backoff := minB

	for ctx.Err() == nil {
		started := time.Now()
		err := joiner.Run(ctx)

		if ctx.Err() != nil {
			return
		}

		// A run that stayed up a while was healthy; restart quickly.
		if time.Since(started) > maxB {
			backoff = minB
		}

		if errors.Is(err, ErrCgroupJoinUnsupported) {
			log.Error("buildkit cgroup joiner unsupported; not restarting", "error", err)

			return
		}

		log.Error("buildkit cgroup joiner exited; restarting", "error", err, "backoff", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxB)
	}
}

// ExpandCgroupGlobs walks each configured cgroup pattern and resolves
// it to concrete directories via filepath.Glob, deduplicating the
// result. Plain (non-glob) paths flow through unchanged when they
// exist; a non-existent plain path is logged at WARN but otherwise
// dropped. Glob patterns that match zero paths log at WARN.
//
// The Go stdlib glob supports `*` per path component but not `**`;
// callers that want deep wildcards should write a `*` per directory
// level (e.g. `kubepods.slice/*/*/buildkit`).
func ExpandCgroupGlobs(patterns []string, log *slog.Logger) []string {
	if len(patterns) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))

	for _, p := range patterns {
		if !strings.ContainsAny(p, "*?[") {
			info, err := os.Stat(p)
			if err != nil || !info.IsDir() {
				log.Warn("buildkit cgroup path missing or not a directory; skipping",
					"path", p, "error", err)

				continue
			}

			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}

			continue
		}

		matches, err := filepath.Glob(p)
		if err != nil {
			log.Warn("buildkit cgroup glob is malformed; skipping",
				"pattern", p, "error", err)

			continue
		}

		if len(matches) == 0 {
			log.Warn("buildkit cgroup glob matched zero paths",
				"pattern", p)

			continue
		}

		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}

			if _, dup := seen[m]; !dup {
				seen[m] = struct{}{}
				out = append(out, m)
			}
		}
	}

	return out
}

// CgroupResolverConfig configures a CgroupResolver.
type CgroupResolverConfig struct {
	// Patterns are the cgroup paths / globs to resolve.
	Patterns []string
	// Logger receives all resolver logs (required).
	Logger *slog.Logger
	// LogAttrs are extra structured attributes (config-derived only)
	// appended to the "step attribution active" log line.
	LogAttrs []any
	// NewJoiner builds the joiner for one path set; it is run under
	// a supervisor. scanExisting is true for lazy first activation
	// and restarts (the source must then report children that
	// already exist, see InotifyCgroupSource.ScanExisting) and false
	// for the cold-start synchronous activation. Required.
	NewJoiner func(paths []string, scanExisting bool) JoinerRunner
	// StartAttach starts the egress attach for one path set. nil
	// means the attach is disabled. On failure it MUST return a nil
	// interface (not a typed nil pointer); on success it may return
	// a nil Closer.
	StartAttach func(ctx context.Context, paths []string) (io.Closer, error)

	// PollInterval defaults to DefaultCgroupPollInterval.
	PollInterval time.Duration
	// MinRestartInterval defaults to DefaultCgroupMinRestartInterval.
	MinRestartInterval time.Duration
	// AttachRetryMax defaults to DefaultCgroupAttachRetryMax.
	AttachRetryMax time.Duration
	// MaxPaths defaults to DefaultCgroupMaxPaths.
	MaxPaths int

	// NewWatcher builds the directory watcher that triggers an
	// immediate re-resolve when a cgroup appears under a directory
	// the patterns live in. nil selects the platform default
	// (inotify on Linux). A watcher that cannot be built or armed
	// degrades to the PollInterval poll.
	NewWatcher func() (CgroupDirWatcher, error)
	// DisableWatcher turns the watcher off (poll only).
	DisableWatcher bool
	// MinAddInterval is the minimum gap between two applies that add
	// coverage (the first apply for a new set is immediate). It bounds
	// restarts under storms of new cgroups. Defaults to
	// DefaultCgroupMinAddInterval.
	MinAddInterval time.Duration
	// EventSettle is how long a burst of watcher events is coalesced
	// before one re-resolve runs. Defaults to DefaultCgroupEventSettle.
	EventSettle time.Duration
}

// cgroupGeneration is one running generation of the cgroup-dependent
// machinery (joiner + optional egress attach) bound to a fixed path
// set. The joiner and attach take their paths at construction and
// cannot be updated, so a changed path set means a new generation.
type cgroupGeneration struct {
	paths  []string
	ids    []string // path identity (path + inode), parallel to paths
	cancel context.CancelFunc
	done   chan struct{}
	attach io.Closer
}

func (g *cgroupGeneration) stopJoiner() {
	g.cancel()
	<-g.done
}

// CgroupResolver resolves BuildKit cgroup patterns repeatedly and
// (re)starts the joiner/attach whenever the resolved path set becomes
// non-empty or changes (a path is identified by its name and inode,
// so remove+recreate counts as a change).
//
// Lifecycle: Start must be called at most once; Close (or cancelling
// the Start context) tears everything down and is idempotent. Close
// before Start makes a later Start fail without starting anything.
type CgroupResolver struct {
	cfg CgroupResolverConfig
	log *slog.Logger

	mu      sync.Mutex
	state   int // 0 new, 1 started, 2 closed
	gen     *cgroupGeneration
	cancel  context.CancelFunc
	pollEnd chan struct{}

	// Poller-goroutine-only state.
	attachBackoff    time.Duration
	attachNext       time.Time
	nextRestart      time.Time
	restartGap       time.Duration
	lastRestart      time.Time
	cappedLogged     bool
	attachFailLogged int
	failNext         time.Time
	failGap          time.Duration
	failedIDs        []string // identities of the last failed addition
	nextAdd          time.Time
	retryAt          time.Time // poller-only: deferred re-resolve for a throttled addition
	overLimitLogged  bool
	watchCapLogged   bool

	watcher     CgroupDirWatcher
	watchLogged bool
}

// NewCgroupResolver validates and defaults cfg.
func NewCgroupResolver(cfg CgroupResolverConfig) *CgroupResolver {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultCgroupPollInterval
	}

	if cfg.MinRestartInterval <= 0 {
		cfg.MinRestartInterval = DefaultCgroupMinRestartInterval
	}

	if cfg.AttachRetryMax <= 0 {
		cfg.AttachRetryMax = DefaultCgroupAttachRetryMax
	}

	if cfg.MaxPaths <= 0 {
		cfg.MaxPaths = DefaultCgroupMaxPaths
	}

	if cfg.MinAddInterval <= 0 {
		cfg.MinAddInterval = DefaultCgroupMinAddInterval
	}

	if cfg.EventSettle <= 0 {
		cfg.EventSettle = DefaultCgroupEventSettle
	}

	if cfg.NewWatcher == nil {
		cfg.NewWatcher = newPlatformDirWatcher
	}

	return &CgroupResolver{cfg: cfg, log: cfg.Logger, restartGap: cfg.MinRestartInterval}
}

// Start expands the patterns synchronously. If any path matches, the
// joiner (without scanning pre-existing children) and attach start
// immediately and an attach failure is returned, so startup stays
// fatal for the caller. Otherwise a Warn is logged. In both cases a
// background poller then keeps re-resolving until ctx is cancelled or
// Close is called.
func (m *CgroupResolver) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.state != 0 {
		m.mu.Unlock()

		return errors.New("cgroup resolver: already started or closed")
	}

	m.state = 1
	pctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.pollEnd = make(chan struct{})
	m.mu.Unlock()

	m.openWatcher()

	paths, ids := m.resolve(m.log)
	if len(paths) > 0 {
		if err := m.activate(pctx, paths, ids, true); err != nil {
			cancel()
			m.closeWatcher()
			close(m.pollEnd)

			return err
		}
	} else {
		m.log.Warn("buildkit step attribution: cgroup patterns supplied but no paths matched yet; "+
			"will keep re-resolving until buildkitd creates its cgroup parent",
			append(slices.Clone(m.cfg.LogAttrs), "cgroup_patterns", strings.Join(m.cfg.Patterns, ","))...)
	}

	go func() {
		defer close(m.pollEnd)

		m.run(pctx)
	}()

	return nil
}

// Close stops the poller, the joiner and the attach, waiting for all
// of them, and returns the attach close error. Safe to call multiple
// times, concurrently, and on a nil receiver.
func (m *CgroupResolver) Close() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	prev := m.state
	m.state = 2
	cancel, end := m.cancel, m.pollEnd
	m.mu.Unlock()

	if prev != 1 {
		return nil
	}

	cancel()
	<-end

	return m.deactivate()
}

// resolve expands the patterns to a sorted, capped path set plus a
// parallel identity (path+inode) list. Paths that vanish between the
// glob and the stat are dropped. When over the cap, paths already in
// the running generation are kept in preference to new ones so a new
// path never pushes a covered one out.
func (m *CgroupResolver) resolve(log *slog.Logger) ([]string, []string) {
	expanded := ExpandCgroupGlobs(m.cfg.Patterns, log)
	slices.Sort(expanded)

	idOf := make(map[string]string, len(expanded))
	paths := make([]string, 0, len(expanded))

	for _, p := range expanded {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}

		var ino uint64

		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = uint64(st.Ino) //nolint:unconvert // width differs per GOOS
		}

		idOf[p] = p + "\x00" + strconv.FormatUint(ino, 10)
		paths = append(paths, p)
	}

	if len(paths) > m.cfg.MaxPaths {
		if !m.cappedLogged {
			m.cappedLogged = true

			m.log.Warn("buildkit cgroup resolved path count exceeds cap; extra paths ignored",
				"resolved", len(paths), "cap", m.cfg.MaxPaths)
		}

		if gen := m.current(); gen != nil {
			slices.SortStableFunc(paths, func(a, b string) int {
				ca, cb := slices.Contains(gen.ids, idOf[a]), slices.Contains(gen.ids, idOf[b])

				switch {
				case ca && !cb:
					return -1
				case cb && !ca:
					return 1
				default:
					return 0
				}
			})
		}

		paths = paths[:m.cfg.MaxPaths]
		slices.Sort(paths)
	}

	ids := make([]string, len(paths))
	for i, p := range paths {
		ids[i] = idOf[p]
	}

	return paths, ids
}

func (m *CgroupResolver) startJoiner(ctx context.Context, paths []string, scan bool) (context.CancelFunc, chan struct{}) {
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	joiner := m.cfg.NewJoiner(paths, scan)

	go func() {
		defer close(done)

		superviseJoiner(cctx, joiner, m.log)
	}()

	return cancel, done
}

// activate moves to a generation for paths. With a running generation
// the attach is make-before-break: the new attach starts first, and if
// it fails the old generation keeps running and the error is returned.
// With no running generation a failing attach is returned only when
// cold (startup, fatal); otherwise the joiner starts anyway and the
// attach is retried with backoff. The joiner itself is break-before-
// make. scanExisting is true unless cold.
func (m *CgroupResolver) activate(ctx context.Context, paths, ids []string, cold bool) error {
	m.mu.Lock()
	old := m.gen
	m.mu.Unlock()

	var newAttach io.Closer

	attachFailed := false

	if m.cfg.StartAttach != nil {
		a, err := m.cfg.StartAttach(ctx, paths)
		if ctx.Err() != nil {
			// Shutting down: do not start anything.
			if err == nil && a != nil {
				_ = a.Close()
			}

			return ctx.Err()
		}

		switch {
		case err != nil && (old != nil || cold):
			return err
		case err != nil:
			attachFailed = true

			m.noteAttachFailure(err)
		default:
			newAttach = a
		}
	}

	if old != nil {
		old.stopJoiner()
	}

	cancel, done := m.startJoiner(ctx, paths, !cold)
	gen := &cgroupGeneration{paths: slices.Clone(paths), ids: slices.Clone(ids), cancel: cancel, done: done, attach: newAttach}

	m.mu.Lock()
	m.gen = gen
	m.mu.Unlock()

	if old != nil && old.attach != nil {
		_ = old.attach.Close()
	}

	if !attachFailed {
		m.attachBackoff = 0
	}

	if old == nil {
		m.log.Info("buildkit step attribution active", append(slices.Clone(m.cfg.LogAttrs),
			"cgroup_path_count", len(paths),
		)...)
	}

	return nil
}

// noteAttachFailure schedules the next attach retry with exponential
// backoff and logs once per backoff step.
func (m *CgroupResolver) noteAttachFailure(err error) {
	if m.attachBackoff == 0 {
		m.attachBackoff = m.cfg.PollInterval
	} else {
		m.attachBackoff = min(m.attachBackoff*2, m.cfg.AttachRetryMax)
	}

	m.attachNext = time.Now().Add(m.attachBackoff)

	m.log.Error("buildkit egress attach failed; joiner keeps running, retrying",
		"error", err, "retry_in", m.attachBackoff)
}

// retryAttach retries a missing attach for the running generation.
func (m *CgroupResolver) retryAttach(ctx context.Context) {
	m.mu.Lock()
	gen := m.gen
	m.mu.Unlock()

	if m.cfg.StartAttach == nil || gen == nil || gen.attach != nil || m.attachBackoff == 0 ||
		time.Now().Before(m.attachNext) {
		return
	}

	a, err := m.cfg.StartAttach(ctx, gen.paths)
	if err != nil {
		m.noteAttachFailure(err)

		return
	}

	if ctx.Err() != nil || a == nil {
		if a != nil {
			_ = a.Close()
		}

		if a == nil {
			m.attachBackoff = 0
		}

		return
	}

	m.mu.Lock()
	gen.attach = a
	m.mu.Unlock()

	m.attachBackoff = 0

	m.log.Info("buildkit egress attach recovered")
}

func (m *CgroupResolver) deactivate() error {
	m.mu.Lock()
	gen := m.gen
	m.gen = nil
	m.mu.Unlock()

	if gen == nil {
		return nil
	}

	gen.stopJoiner()

	if gen.attach != nil {
		return gen.attach.Close()
	}

	return nil
}

func (m *CgroupResolver) current() *cgroupGeneration {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.gen
}

// openWatcher builds and arms the directory watcher. Failure is not
// fatal: the poll remains the fallback.
func (m *CgroupResolver) openWatcher() {
	if m.cfg.DisableWatcher {
		return
	}

	w, err := m.cfg.NewWatcher()
	if err != nil || w == nil {
		m.log.Warn("buildkit cgroup watcher unavailable; falling back to polling",
			"error", err, "poll_interval", m.cfg.PollInterval)

		return
	}

	m.watcher = w
	m.syncWatches()
}

func (m *CgroupResolver) closeWatcher() {
	if m.watcher != nil {
		_ = m.watcher.Close()
		m.watcher = nil
	}
}

// syncWatches re-arms the watcher for the current directory layout. It
// must run before each re-resolve so a directory created between the
// previous arm and now is both watched and seen by the resolve.
func (m *CgroupResolver) syncWatches() {
	if m.watcher == nil {
		return
	}

	dirs, truncated := cgroupWatchDirs(m.cfg.Patterns, maxCgroupWatchDirs)
	if truncated && !m.watchCapLogged {
		m.watchCapLogged = true

		m.log.Warn("buildkit cgroup watch directory cap reached; lowest-priority directories are poll-only",
			"cap", maxCgroupWatchDirs)
	}

	if err := m.watcher.Watch(dirs); err != nil && !m.watchLogged {
		m.watchLogged = true

		m.log.Warn("buildkit cgroup watcher could not watch every directory; poll remains the fallback",
			"error", err)
	}
}

// run re-resolves on watcher events (immediately, coalesced over
// EventSettle) and on every poll tick, until ctx is done, then tears
// the generation down.
//
// Policy: a resolved set containing a path not in the running
// generation (a new directory, or a recreated inode) is applied at
// once, with no debounce and no rate limit: delaying new coverage is
// what leaves RUN steps unobserved. Removal-only churn keeps the
// two-poll debounce and the MinRestartInterval rate limit (doubling
// while consecutive), and only timer polls count towards the debounce.
// A failed apply is retried for the same set only after a doubling
// backoff. An empty result after activation keeps the current
// generation (the inotify source re-establishes watches itself).
func (m *CgroupResolver) run(ctx context.Context) {
	defer func() { _ = m.deactivate() }()
	defer m.closeWatcher()

	var (
		pending []string
		events  <-chan struct{}
	)

	if m.watcher != nil {
		events = m.watcher.Events()
	}

	// The ticker lives outside the loop: events must never postpone
	// the timer poll (attach retry, debounced removals).
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	deferred := time.NewTimer(time.Hour)
	if !deferred.Stop() {
		<-deferred.C
	}

	defer deferred.Stop()

	arm := func() {
		if m.retryAt.IsZero() {
			return
		}

		deferred.Reset(max(time.Until(m.retryAt), time.Millisecond))
		m.retryAt = time.Time{}
	}

	// Pick up anything created between Start's resolve and now.
	if events != nil {
		m.syncWatches()
		m.poll(ctx, &pending, false)
		arm()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncWatches()
			m.pollOnce(ctx, &pending)
		case <-deferred.C:
			m.syncWatches()
			m.poll(ctx, &pending, false)
		case _, ok := <-events:
			if !ok {
				// Watcher died (not by our Close): poll only from here.
				m.log.Warn("buildkit cgroup watcher stopped; falling back to polling",
					"poll_interval", m.cfg.PollInterval)
				m.closeWatcher()

				events = nil

				continue
			}

			// Coalesce the burst, then resolve once.
			select {
			case <-ctx.Done():
				return
			case <-time.After(m.cfg.EventSettle):
			}

			select {
			case <-events:
			default:
			}

			m.syncWatches()
			m.poll(ctx, &pending, false)
		}

		arm()
	}
}

// pollOnce performs one timer-driven re-resolution step.
func (m *CgroupResolver) pollOnce(ctx context.Context, pending *[]string) {
	m.poll(ctx, pending, true)
}

// hasNewID reports whether ids holds an identity absent from old.
func hasNewID(ids, old []string) bool {
	for _, id := range ids {
		if !slices.Contains(old, id) {
			return true
		}
	}

	return false
}

// poll performs one re-resolution step. timer is false for
// event-driven steps, which may add coverage but never confirm a
// removal-only change (that stays on the timer debounce).
func (m *CgroupResolver) poll(ctx context.Context, pending *[]string, timer bool) {
	paths, ids := m.resolve(slog.New(slog.DiscardHandler))
	gen := m.current()

	switch {
	case len(paths) == 0 && gen == nil:
	case len(paths) == 0:
		if timer {
			*pending = nil
		}

		m.retryAttach(ctx)
	case gen == nil:
		if err := m.activate(ctx, paths, ids, false); err != nil && ctx.Err() == nil {
			m.log.Error("buildkit step attribution: activation failed; will retry", "error", err)
		} else if err == nil {
			m.resetFailure()
		}
	case slices.Equal(ids, gen.ids):
		*pending = nil

		m.resetFailure() // healthy: a later transient failure starts from the minimum gap

		m.retryAttach(ctx)
	case hasNewID(ids, gen.ids):
		m.applyAddition(ctx, gen, paths, ids, pending)
	case !timer:
		// Removal-only: left to the debounced timer path.
	case !slices.Equal(ids, *pending):
		*pending = ids
	case time.Now().Before(m.nextRestart):
		// Confirmed removal, but rate limited: keep pending.
	default:
		m.log.Info("buildkit cgroup paths changed; restarting joiner",
			"previous", len(gen.paths), "resolved", len(paths))

		m.noteRestart()

		if err := m.activate(ctx, paths, ids, false); err != nil && ctx.Err() == nil {
			m.log.Error("buildkit step attribution: restart failed; old generation kept", "error", err)
		} else {
			*pending = nil

			m.resetFailure()
		}
	}
}

// resetFailure clears the failed-apply backoff state.
func (m *CgroupResolver) resetFailure() {
	m.failNext, m.failGap, m.failedIDs = time.Time{}, 0, nil
}

// applyAddition applies a path set that adds coverage. The first
// apply is immediate and ignores the removal debounce and restart rate
// limit. Further additions are floored at MinAddInterval (a deferred
// re-resolve is scheduled, so a throttled change is not left to the
// 15 s poll), and after a failed apply nothing is retried before the
// doubling failure backoff elapses, whatever the set. The apply is
// restart-based (the joiner and attach take their paths at
// construction) but make-before-break for the attach, so paths that
// stay in the set remain covered by the old attach until the new one
// is live.
func (m *CgroupResolver) applyAddition(ctx context.Context, gen *cgroupGeneration, paths, ids []string, pending *[]string) {
	now := time.Now()

	// The failure backoff holds back a repeat of the failed set, and
	// any set over the datapath parent limit (it can never succeed). A
	// set with an identity absent from the last failed one is a
	// genuinely new parent and only waits for the add floor.
	overLimit := m.cfg.StartAttach != nil && len(paths) > bkMaxParents
	backoff := m.failNext.Sub(now)

	if backoff > 0 && !overLimit && hasNewID(ids, m.failedIDs) {
		backoff = 0
	}

	if wait := max(m.nextAdd.Sub(now), backoff); wait > 0 {
		m.retryAt = now.Add(wait)

		return
	}

	if overLimit && !m.overLimitLogged {
		m.overLimitLogged = true

		m.log.Warn("buildkit cgroup path count exceeds the datapath parent limit; the attach will be rejected",
			"resolved", len(paths), "datapath_limit", bkMaxParents)
	}

	m.log.Info("buildkit cgroup paths added; restarting joiner",
		"previous", len(gen.paths), "resolved", len(paths))

	m.nextAdd = now.Add(m.cfg.MinAddInterval)

	if err := m.activate(ctx, paths, ids, false); err != nil {
		if ctx.Err() != nil {
			return
		}

		first := m.failGap == 0

		if first {
			m.failGap = m.cfg.MinAddInterval
		} else {
			m.failGap = min(m.failGap*2, m.cfg.AttachRetryMax)
		}

		m.failNext = time.Now().Add(m.failGap)
		m.failedIDs = slices.Clone(ids)
		m.retryAt = m.failNext

		if first {
			m.log.Error("buildkit step attribution: restart failed; old generation kept, retrying with backoff",
				"error", err, "retry_in", m.failGap)
		}

		return
	}

	*pending = nil

	m.resetFailure()
}

// noteRestart arms the restart rate limit. Consecutive restarts (the
// previous one within four gaps) double the gap, otherwise it resets.
func (m *CgroupResolver) noteRestart() {
	now := time.Now()

	if !m.lastRestart.IsZero() && now.Sub(m.lastRestart) < 4*m.restartGap {
		m.restartGap = min(m.restartGap*2, time.Hour)
	} else {
		m.restartGap = m.cfg.MinRestartInterval
	}

	m.lastRestart = now
	m.nextRestart = now.Add(m.restartGap)
}
