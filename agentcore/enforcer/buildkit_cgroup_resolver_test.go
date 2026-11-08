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
	"sync"
	"testing"
	"time"
)

type fakeCgroupRig struct {
	mu        sync.Mutex
	joiners   [][]string
	scans     []bool
	attaches  [][]string
	events    []string
	entered   int
	exited    int
	closed    int
	attachErr func(call int) error // nil: never fails
	attachHit int
	blockCh   chan struct{} // when set, StartAttach waits on ctx or this
	inAttach  chan struct{}
	watcher   *fakeWatcher // when set, the resolver uses it instead of no watcher
}

func (r *fakeCgroupRig) ev(s string) {
	r.mu.Lock()
	r.events = append(r.events, s)
	r.mu.Unlock()
}

type fakeBlockingJoiner struct{ rig *fakeCgroupRig }

func (j fakeBlockingJoiner) Run(ctx context.Context) error {
	j.rig.mu.Lock()
	j.rig.entered++
	j.rig.mu.Unlock()

	<-ctx.Done()

	j.rig.mu.Lock()
	j.rig.exited++
	j.rig.events = append(j.rig.events, "joiner-exit")
	j.rig.mu.Unlock()

	return ctx.Err()
}

type fakeCloser struct{ rig *fakeCgroupRig }

func (c fakeCloser) Close() error {
	c.rig.mu.Lock()
	c.rig.closed++
	c.rig.events = append(c.rig.events, "attach-close")
	c.rig.mu.Unlock()

	return nil
}

func (r *fakeCgroupRig) resolver(patterns []string, withAttach bool, poll time.Duration) *CgroupResolver {
	cfg := CgroupResolverConfig{
		Patterns: patterns,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		NewJoiner: func(paths []string, scan bool) JoinerRunner {
			r.mu.Lock()
			r.joiners = append(r.joiners, slices.Clone(paths))
			r.scans = append(r.scans, scan)
			r.events = append(r.events, "joiner-start")
			r.mu.Unlock()

			return fakeBlockingJoiner{rig: r}
		},
		PollInterval:       poll,
		MinRestartInterval: time.Millisecond,
		DisableWatcher:     r.watcher == nil,
	}

	if r.watcher != nil {
		w := r.watcher
		cfg.NewWatcher = func() (CgroupDirWatcher, error) { return w, nil }
		cfg.EventSettle = time.Millisecond
	}

	if withAttach {
		cfg.StartAttach = func(ctx context.Context, paths []string) (io.Closer, error) {
			r.mu.Lock()
			r.attachHit++
			call := r.attachHit
			errFn, block, in := r.attachErr, r.blockCh, r.inAttach
			r.events = append(r.events, "attach-start")
			r.mu.Unlock()

			if in != nil {
				close(in)
			}

			if block != nil {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-block:
				}
			}

			if errFn != nil {
				if err := errFn(call); err != nil {
					return nil, err
				}
			}

			r.mu.Lock()
			r.attaches = append(r.attaches, slices.Clone(paths))
			r.mu.Unlock()

			return fakeCloser{rig: r}, nil
		}
	}

	return NewCgroupResolver(cfg)
}

func (r *fakeCgroupRig) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		r.mu.Lock()
		ok := cond()
		r.mu.Unlock()

		if ok {
			return
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

func (r *fakeCgroupRig) snapshot() (joiners [][]string, scans []bool, entered, exited, closed, attaches int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.joiners), slices.Clone(r.scans), r.entered, r.exited, r.closed, len(r.attaches)
}

func mkdir(t *testing.T, p string) {
	t.Helper()

	if err := os.Mkdir(p, 0o750); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupResolver_LateAppearingPathActivatesAndCancelTearsDown(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "buildkit")
	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{target}, true, 5*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cm.Start(ctx); err != nil {
		t.Fatal(err)
	}

	time.Sleep(30 * time.Millisecond)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 0 {
		t.Fatalf("joiner started before the path existed: %d", len(j))
	}

	mkdir(t, target)
	rig.waitFor(t, "joiner Run entered", func() bool { return rig.entered == 1 })

	j, scans, _, _, _, _ := rig.snapshot()
	if !slices.Equal(j[0], []string{target}) || !scans[0] {
		t.Fatalf("paths=%v scan=%v, want [%s] with scan (lazy activation)", j[0], scans, target)
	}

	// Teardown by ctx cancel alone, without Close.
	cancel()
	rig.waitFor(t, "teardown", func() bool { return rig.exited == 1 && rig.closed == 1 })

	if err := cm.Close(); err != nil {
		t.Fatal(err)
	}

	if _, _, _, ex, cl, _ := rig.snapshot(); ex != 1 || cl != 1 {
		t.Fatalf("exited=%d closed=%d, want 1/1", ex, cl)
	}
}

func TestCgroupResolver_ColdStartDoesNotScan(t *testing.T) {
	t.Parallel()

	a := filepath.Join(t.TempDir(), "a")
	mkdir(t, a)

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{a}, true, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, scans, _, _, _, _ := rig.snapshot(); !slices.Equal(scans, []bool{false}) {
		t.Fatalf("scans=%v, want [false] for cold start", scans)
	}

	if err := cm.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupResolver_AdditionalPathRestartsMakeBeforeBreak(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdir(t, a)

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, 5*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	mkdir(t, b)
	rig.waitFor(t, "second generation", func() bool { return len(rig.joiners) == 2 && rig.closed == 1 })

	j, scans, _, _, _, att := rig.snapshot()
	if !slices.Equal(j[0], []string{a}) || !slices.Equal(j[1], []string{a, b}) ||
		!slices.Equal(scans, []bool{false, true}) || att != 2 {
		t.Fatalf("gens=%v scans=%v attaches=%d", j, scans, att)
	}

	rig.mu.Lock()
	want := []string{"attach-start", "joiner-start", "attach-start", "joiner-exit", "joiner-start", "attach-close"}
	got := slices.Clone(rig.events[:6])
	rig.mu.Unlock()

	if !slices.Equal(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}

	if err := cm.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupResolver_SinglePollRemovalDoesNotRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	mkdir(t, a)
	mkdir(t, b)
	mkdir(t, c)

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	var pending []string

	if err := os.Remove(c); err != nil {
		t.Fatal(err)
	}

	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("restarted on a single poll: %d", len(j))
	}

	// The removal set changes between polls: confirmation restarts.
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}

	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("restarted without two consecutive identical polls: %d", len(j))
	}

	cm.pollOnce(context.Background(), &pending)

	j, _, _, _, _, _ := rig.snapshot()
	if len(j) != 2 || !slices.Equal(j[1], []string{a}) {
		t.Fatalf("no restart after two consecutive polls: %v", j)
	}

	_ = cm.Close()
}

func TestCgroupResolver_AdditionNeedsNoDebounce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	var pending []string

	mkdir(t, filepath.Join(dir, "b"))
	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 2 {
		t.Fatalf("addition was debounced: %d generations", len(j))
	}

	_ = cm.Close()
}

func TestCgroupResolver_InodeChangeRestarts(t *testing.T) {
	t.Parallel()

	a := filepath.Join(t.TempDir(), "a")
	mkdir(t, a)

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{a}, false, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Keep the old inode allocated so the recreate gets a new one.
	hold := a + ".hold"
	if err := os.Rename(a, hold); err != nil {
		t.Fatal(err)
	}

	mkdir(t, a)

	var pending []string

	cm.pollOnce(context.Background(), &pending)
	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 2 {
		t.Fatalf("remove+recreate did not re-attach: %d generations", len(j))
	}

	_ = cm.Close()
}

func TestCgroupResolver_RemovalFlapIsRateLimited(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	names := []string{"a", "b", "c", "d", "e"}

	for _, n := range names {
		mkdir(t, filepath.Join(dir, n))
	}

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)
	cm.cfg.MinRestartInterval = time.Hour
	cm.restartGap = time.Hour

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	var pending []string

	for i, name := range []string{"e", "d", "c"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}

		for range 3 {
			cm.pollOnce(context.Background(), &pending)
		}

		want := 2 // first removal restart allowed, everything after is held back
		if j, _, _, _, _, _ := rig.snapshot(); len(j) != want {
			t.Fatalf("step %d: generations=%d, want %d", i, len(j), want)
		}
	}

	_ = cm.Close()
}

type fakeWatcher struct {
	mu      sync.Mutex
	ev      chan struct{}
	watched [][]string
}

func newFakeWatcher() *fakeWatcher { return &fakeWatcher{ev: make(chan struct{}, 1)} }

func (w *fakeWatcher) Watch(dirs []string) error {
	w.mu.Lock()
	w.watched = append(w.watched, slices.Clone(dirs))
	w.mu.Unlock()

	return nil
}

func (w *fakeWatcher) Events() <-chan struct{} { return w.ev }
func (w *fakeWatcher) Close() error            { return nil }

func (w *fakeWatcher) fire() {
	select {
	case w.ev <- struct{}{}:
	default:
	}
}

func (w *fakeWatcher) lastWatched() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.watched) == 0 {
		return nil
	}

	return slices.Clone(w.watched[len(w.watched)-1])
}

func TestCgroupResolver_EventAppliesNewPodImmediately(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdir(t, a)

	rig := &fakeCgroupRig{watcher: newFakeWatcher()}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	if got := rig.watcher.lastWatched(); !slices.Equal(got, []string{dir}) {
		t.Fatalf("watched=%v, want [%s]", got, dir)
	}

	mkdir(t, b)
	rig.watcher.fire()
	rig.waitFor(t, "second generation without a poll", func() bool { return len(rig.joiners) == 2 })

	j, scans, _, _, _, _ := rig.snapshot()
	if !slices.Equal(j[1], []string{a, b}) || !scans[1] {
		t.Fatalf("gens=%v scans=%v", j, scans)
	}
}

func TestCgroupResolver_ReplacementAppliesImmediately(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdir(t, a)

	rig := &fakeCgroupRig{watcher: newFakeWatcher()}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)
	cm.cfg.MinRestartInterval = time.Hour
	cm.restartGap = time.Hour
	cm.nextRestart = time.Now().Add(time.Hour) // rate limit armed

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}

	mkdir(t, b)
	rig.watcher.fire()
	rig.waitFor(t, "replacement generation", func() bool { return len(rig.joiners) == 2 })

	if j, _, _, _, _, _ := rig.snapshot(); !slices.Equal(j[1], []string{b}) {
		t.Fatalf("gens=%v, want second generation [%s]", j, b)
	}
}

func TestCgroupResolver_RemovalOnlyStaysDebounced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdir(t, a)
	mkdir(t, b)

	// No live watcher: poll state is only touched from this goroutine.
	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}

	var pending []string

	for range 5 { // event-driven polls never confirm a removal
		cm.poll(context.Background(), &pending, false)
	}

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("event polls applied a removal: %d generations", len(j))
	}

	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("single timer poll applied a removal: %d", len(j))
	}

	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 2 || !slices.Equal(j[1], []string{a}) {
		t.Fatalf("removal not applied after two timer polls: %v", j)
	}
}

func TestCgroupResolver_RepeatedFailingSetBacksOff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{attachErr: func(call int) error {
		if call >= 2 {
			return errors.New("boom")
		}

		return nil
	}}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)
	cm.cfg.MinAddInterval = time.Millisecond

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	var pending []string

	mkdir(t, filepath.Join(dir, "b"))
	cm.pollOnce(context.Background(), &pending) // attach call 2 fails

	if rig.attachHit != 2 || cm.failNext.IsZero() {
		t.Fatalf("attachHit=%d failNext=%v, want a recorded failure", rig.attachHit, cm.failNext)
	}

	cm.failNext = time.Now().Add(time.Hour)
	time.Sleep(3 * time.Millisecond)
	cm.pollOnce(context.Background(), &pending) // same failed set inside backoff

	if rig.attachHit != 2 {
		t.Fatalf("failed set retried inside backoff: %d attach calls", rig.attachHit)
	}

	cm.failNext = time.Time{} // backoff elapsed
	cm.pollOnce(context.Background(), &pending)

	if rig.attachHit != 3 {
		t.Fatalf("no retry after backoff elapsed: %d attach calls", rig.attachHit)
	}

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("old generation disturbed by failed applies: %d", len(j))
	}
}

func TestCgroupResolver_GenuinelyNewPathNotDelayedByStaleBackoff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{attachErr: func(call int) error {
		if call == 2 || call == 4 {
			return errors.New("boom")
		}

		return nil
	}}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)
	cm.cfg.MinAddInterval = 20 * time.Millisecond

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	var pending []string

	mkdir(t, filepath.Join(dir, "b"))
	cm.pollOnce(context.Background(), &pending) // call 2 fails

	if cm.failGap != 20*time.Millisecond {
		t.Fatalf("first failure gap=%v, want MinAddInterval", cm.failGap)
	}

	time.Sleep(25 * time.Millisecond)
	cm.pollOnce(context.Background(), &pending) // retry succeeds (call 3)

	if !cm.failNext.IsZero() || cm.failGap != 0 {
		t.Fatalf("failure state not reset by a successful apply: gap=%v", cm.failGap)
	}

	time.Sleep(25 * time.Millisecond)
	mkdir(t, filepath.Join(dir, "c"))
	cm.pollOnce(context.Background(), &pending) // call 4 fails again

	if cm.failGap != 20*time.Millisecond {
		t.Fatalf("gap after recovery=%v, want a fresh MinAddInterval (not doubled)", cm.failGap)
	}

	// A stale, long backoff must not delay a genuinely new parent.
	cm.failNext = time.Now().Add(time.Hour)

	time.Sleep(25 * time.Millisecond)
	mkdir(t, filepath.Join(dir, "d"))
	cm.pollOnce(context.Background(), &pending)

	j, _, _, _, _, _ := rig.snapshot()
	if len(j) != 3 || len(j[len(j)-1]) != 4 {
		t.Fatalf("new parent delayed by failure backoff: %v", j)
	}
}

func TestCgroupResolver_HealthyPollResetsFailureBackoff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	cm.failGap, cm.failNext = 5*time.Minute, time.Now().Add(time.Hour)

	var pending []string

	cm.pollOnce(context.Background(), &pending)

	if cm.failGap != 0 || !cm.failNext.IsZero() {
		t.Fatalf("healthy poll left stale backoff: gap=%v", cm.failGap)
	}
}

func TestCgroupResolver_OverLimitSetStillBacksOff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "p0"))

	rig := &fakeCgroupRig{attachErr: func(call int) error {
		if call >= 2 {
			return errors.New("too many parents")
		}

		return nil
	}}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)
	cm.cfg.MinAddInterval = time.Millisecond

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	for i := 1; i <= bkMaxParents; i++ { // 9 parents: over the datapath limit
		mkdir(t, filepath.Join(dir, "p"+strconv.Itoa(i)))
	}

	var pending []string

	cm.pollOnce(context.Background(), &pending) // fails

	if rig.attachHit != 2 {
		t.Fatalf("attachHit=%d, want 2", rig.attachHit)
	}

	cm.failNext = time.Now().Add(time.Hour)
	time.Sleep(3 * time.Millisecond)
	mkdir(t, filepath.Join(dir, "p9")) // new id, but still over the limit
	cm.pollOnce(context.Background(), &pending)

	if rig.attachHit != 2 {
		t.Fatalf("over-limit set retried inside backoff: %d attach calls", rig.attachHit)
	}
}

func TestCgroupResolver_AdditionStormIsFloored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "p00"))

	rig := &fakeCgroupRig{watcher: newFakeWatcher()}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)
	cm.cfg.MinAddInterval = 150 * time.Millisecond

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	for i := 1; i <= 12; i++ {
		mkdir(t, filepath.Join(dir, "p"+strconv.Itoa(100+i)))
		rig.watcher.fire()
		time.Sleep(5 * time.Millisecond)
	}

	if j, _, _, _, _, _ := rig.snapshot(); len(j) > 2 {
		t.Fatalf("storm of additions caused %d generations inside the floor", len(j))
	}

	// The throttled remainder is applied by the deferred re-resolve, not left to the 15 s poll.
	rig.waitFor(t, "final set applied", func() bool {
		return len(rig.joiners) > 0 && len(rig.joiners[len(rig.joiners)-1]) == 13
	})

	if j, _, _, _, _, _ := rig.snapshot(); len(j) > 3 {
		t.Fatalf("generations=%d, want at most 3", len(j))
	}
}

func TestCgroupResolver_EventsDoNotStarveTimerPoll(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdir(t, a)
	mkdir(t, b)

	rig := &fakeCgroupRig{watcher: newFakeWatcher()}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, 40*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)

		for {
			select {
			case <-stop:
				return
			default:
				rig.watcher.fire() // events far faster than the poll interval
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	// The removal is applied only by timer polls (two consecutive).
	rig.waitFor(t, "debounced removal applied under an event storm", func() bool { return len(rig.joiners) == 2 })

	close(stop)
	<-done
}

func TestCgroupResolver_AttachRetryRunsUnderEventStorm(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "buildkit")

	rig := &fakeCgroupRig{watcher: newFakeWatcher(), attachErr: func(call int) error {
		if call == 1 {
			return errors.New("boom")
		}

		return nil
	}}
	cm := rig.resolver([]string{target}, true, 40*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	mkdir(t, target)

	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)

		for {
			select {
			case <-stop:
				return
			default:
				rig.watcher.fire()
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	rig.waitFor(t, "attach recovered", func() bool { return len(rig.attaches) == 1 })

	close(stop)
	<-done
}

func TestCgroupResolver_ExistingPathsKeptOverCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	b, c := filepath.Join(dir, "b"), filepath.Join(dir, "c")
	mkdir(t, b)
	mkdir(t, c)

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)
	cm.cfg.MaxPaths = 2

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	mkdir(t, filepath.Join(dir, "a")) // sorts first, must not displace b or c

	paths, _ := cm.resolve(slog.New(slog.DiscardHandler))
	if !slices.Equal(paths, []string{b, c}) {
		t.Fatalf("paths=%v, want existing [%s %s] kept", paths, b, c)
	}
}

func TestCgroupResolver_LazyLiteralPathPickedUpOnEvent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "buildkit")

	rig := &fakeCgroupRig{watcher: newFakeWatcher()}
	cm := rig.resolver([]string{target}, true, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	if got := rig.watcher.lastWatched(); !slices.Equal(got, []string{dir}) {
		t.Fatalf("watched=%v, want nearest existing ancestor [%s]", got, dir)
	}

	mkdir(t, target)
	rig.watcher.fire()
	rig.waitFor(t, "lazy activation", func() bool { return len(rig.joiners) == 1 })

	if _, scans, _, _, _, _ := rig.snapshot(); !scans[0] {
		t.Fatal("lazy activation must scan existing children")
	}
}

func TestCgroupResolver_EventStormIsCoalesced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{watcher: newFakeWatcher()}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	defer cm.Close()

	for range 200 { // no path change: no restart at all
		rig.watcher.fire()
		time.Sleep(100 * time.Microsecond)
	}

	time.Sleep(20 * time.Millisecond)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("event storm without change restarted: %d generations", len(j))
	}

	mkdir(t, filepath.Join(dir, "b"))

	for range 200 { // one real change inside a storm: exactly one restart
		rig.watcher.fire()
		time.Sleep(100 * time.Microsecond)
	}

	rig.waitFor(t, "single restart", func() bool { return len(rig.joiners) == 2 })
	time.Sleep(20 * time.Millisecond)

	if j, _, _, _, _, att := rig.snapshot(); len(j) != 2 || att != 2 {
		t.Fatalf("generations=%d attaches=%d, want 2/2", len(j), att)
	}
}

func TestCgroupWatchDirs(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	p1, p2 := filepath.Join(base, "p1"), filepath.Join(base, "p2")
	mkdir(t, p1)
	mkdir(t, p2)
	mkdir(t, filepath.Join(p2, "buildkit"))

	pats := []string{filepath.Join(base, "*", "buildkit"), filepath.Join(base, "p3", "x")}

	got, trunc := cgroupWatchDirs(pats, 16)
	// Resolved-path parents rank before dirs that only await a literal.
	if want := []string{base, p2, p1}; !slices.Equal(got, want) || trunc {
		t.Fatalf("dirs=%v truncated=%v, want %v", got, trunc, want)
	}

	got, trunc = cgroupWatchDirs(pats, 2)
	if want := []string{base, p2}; !slices.Equal(got, want) || !trunc {
		t.Fatalf("capped dirs=%v truncated=%v, want %v truncated", got, trunc, want)
	}
}
