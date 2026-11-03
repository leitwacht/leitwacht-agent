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
)

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

	paths, ids := m.resolve(m.log)
	if len(paths) > 0 {
		if err := m.activate(pctx, paths, ids, true); err != nil {
			cancel()
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
// parallel identity (path+inode) list.
func (m *CgroupResolver) resolve(log *slog.Logger) ([]string, []string) {
	paths := ExpandCgroupGlobs(m.cfg.Patterns, log)
	slices.Sort(paths)

	if len(paths) > m.cfg.MaxPaths {
		if !m.cappedLogged {
			m.cappedLogged = true

			m.log.Warn("buildkit cgroup resolved path count exceeds cap; extra paths ignored",
				"resolved", len(paths), "cap", m.cfg.MaxPaths)
		}

		paths = paths[:m.cfg.MaxPaths]
	}

	ids := make([]string, len(paths))

	for i, p := range paths {
		var ino uint64

		if fi, err := os.Stat(p); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				ino = uint64(st.Ino) //nolint:unconvert // width differs per GOOS
			}
		}

		ids[i] = p + "\x00" + strconv.FormatUint(ino, 10)
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

// run polls until ctx is done, then tears the generation down. A
// change to an already-active path set must be observed on two
// consecutive polls before it is applied (debounce), and applications
// are rate limited (MinRestartInterval, doubling while restarts are
// consecutive). An empty result after activation keeps the current
// generation (the inotify source re-establishes watches itself).
func (m *CgroupResolver) run(ctx context.Context) {
	defer func() { _ = m.deactivate() }()

	var pending []string

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.cfg.PollInterval):
		}

		m.pollOnce(ctx, &pending)
	}
}

// pollOnce performs one re-resolution step.
func (m *CgroupResolver) pollOnce(ctx context.Context, pending *[]string) {
	paths, ids := m.resolve(slog.New(slog.DiscardHandler))
	gen := m.current()

	switch {
	case len(paths) == 0 && gen == nil:
	case len(paths) == 0:
		*pending = nil

		m.retryAttach(ctx)
	case gen == nil:
		if err := m.activate(ctx, paths, ids, false); err != nil && ctx.Err() == nil {
			m.log.Error("buildkit step attribution: activation failed; will retry", "error", err)
		}
	case slices.Equal(ids, gen.ids):
		*pending = nil

		m.retryAttach(ctx)
	case !slices.Equal(ids, *pending):
		*pending = ids
	case time.Now().Before(m.nextRestart):
		// Confirmed change, but rate limited: keep pending.
	default:
		m.log.Info("buildkit cgroup paths changed; restarting joiner",
			"previous", len(gen.paths), "resolved", len(paths))

		m.noteRestart()

		if err := m.activate(ctx, paths, ids, false); err != nil && ctx.Err() == nil {
			m.log.Error("buildkit step attribution: restart failed; old generation kept", "error", err)
		} else {
			*pending = nil
		}
	}
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
