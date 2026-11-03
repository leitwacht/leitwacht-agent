package enforcer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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

func TestCgroupResolver_SinglePollChangeDoesNotRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkdir(t, a)

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	var pending []string

	mkdir(t, b)
	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("restarted on a single poll: %d", len(j))
	}

	if err := os.Remove(b); err != nil { // flap back: change was transient
		t.Fatal(err)
	}

	cm.pollOnce(context.Background(), &pending)
	mkdir(t, b)
	cm.pollOnce(context.Background(), &pending) // pending restarts at b

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 1 {
		t.Fatalf("restarted without two consecutive polls: %d", len(j))
	}

	cm.pollOnce(context.Background(), &pending)

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 2 {
		t.Fatalf("no restart after two consecutive polls: %d", len(j))
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

func TestCgroupResolver_FlapIsRateLimited(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, false, time.Hour)
	cm.cfg.MinRestartInterval = time.Hour
	cm.restartGap = time.Hour

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	var pending []string

	for i, name := range []string{"b", "c", "d", "e"} {
		mkdir(t, filepath.Join(dir, name))

		for range 3 {
			cm.pollOnce(context.Background(), &pending)
		}

		want := 2 // first restart allowed, everything after is held back
		if j, _, _, _, _, _ := rig.snapshot(); len(j) != want {
			t.Fatalf("step %d: generations=%d, want %d", i, len(j), want)
		}
	}

	_ = cm.Close()
}

func TestCgroupResolver_StartAttachFailureIsFatalAtStart(t *testing.T) {
	t.Parallel()

	a := filepath.Join(t.TempDir(), "a")
	mkdir(t, a)

	rig := &fakeCgroupRig{attachErr: func(int) error { return errors.New("boom") }}
	cm := rig.resolver([]string{a}, true, time.Hour)

	if err := cm.Start(context.Background()); err == nil {
		t.Fatal("startup attach failure must be returned")
	}

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 0 {
		t.Fatalf("joiner started despite fatal attach failure: %d", len(j))
	}

	if err := cm.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupResolver_LateAttachFailureKeepsJoinerAndRetries(t *testing.T) {
	t.Parallel()

	a := filepath.Join(t.TempDir(), "a")
	rig := &fakeCgroupRig{attachErr: func(call int) error {
		if call == 1 {
			return errors.New("boom")
		}

		return nil
	}}
	cm := rig.resolver([]string{a}, true, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	mkdir(t, a)

	var pending []string

	cm.pollOnce(context.Background(), &pending)

	j, _, _, _, _, att := rig.snapshot()
	if len(j) != 1 || att != 0 {
		t.Fatalf("joiner gens=%d attaches=%d, want joiner running without attach", len(j), att)
	}

	// Within the backoff window nothing is retried.
	cm.pollOnce(context.Background(), &pending)

	if rig.attachHit != 1 {
		t.Fatalf("attach retried inside backoff: %d calls", rig.attachHit)
	}

	cm.attachNext = time.Time{}
	cm.pollOnce(context.Background(), &pending)

	if _, _, _, _, _, att := rig.snapshot(); att != 1 {
		t.Fatalf("attach not recovered: %d", att)
	}

	rig.waitFor(t, "joiner Run entered", func() bool { return rig.entered == 1 })
	_ = cm.Close()

	if _, _, _, ex, cl, _ := rig.snapshot(); ex != 1 || cl != 1 {
		t.Fatalf("exited=%d closed=%d", ex, cl)
	}
}

func TestCgroupResolver_RestartAttachFailureKeepsOldGeneration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "a"))

	rig := &fakeCgroupRig{attachErr: func(call int) error {
		if call == 2 {
			return errors.New("boom")
		}

		return nil
	}}
	cm := rig.resolver([]string{filepath.Join(dir, "*")}, true, time.Hour)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	mkdir(t, filepath.Join(dir, "b"))

	var pending []string

	cm.pollOnce(context.Background(), &pending)
	cm.pollOnce(context.Background(), &pending)

	j, _, _, ex, cl, _ := rig.snapshot()
	if len(j) != 1 || ex != 0 || cl != 0 {
		t.Fatalf("old generation disturbed: gens=%d exited=%d closed=%d", len(j), ex, cl)
	}

	rig.waitFor(t, "joiner Run entered", func() bool { return rig.entered == 1 })
	_ = cm.Close()

	if _, _, _, ex, cl, _ := rig.snapshot(); ex != 1 || cl != 1 {
		t.Fatalf("exited=%d closed=%d", ex, cl)
	}
}

func TestCgroupResolver_CloseWithSlowStartAttach(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "buildkit")
	rig := &fakeCgroupRig{blockCh: make(chan struct{}), inAttach: make(chan struct{})}
	cm := rig.resolver([]string{target}, true, 5*time.Millisecond)

	if err := cm.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	mkdir(t, target)

	select {
	case <-rig.inAttach:
	case <-time.After(3 * time.Second):
		t.Fatal("StartAttach never entered")
	}

	done := make(chan error, 1)

	go func() { done <- cm.Close() }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked on a slow StartAttach")
	}

	if j, _, _, _, _, _ := rig.snapshot(); len(j) != 0 {
		t.Fatalf("joiner started after Close: %d", len(j))
	}
}

func TestCgroupResolver_StartAfterCloseFails(t *testing.T) {
	t.Parallel()

	rig := &fakeCgroupRig{}
	cm := rig.resolver([]string{"/nonexistent"}, false, time.Hour)

	if err := cm.Close(); err != nil {
		t.Fatal(err)
	}

	if err := cm.Start(context.Background()); err == nil {
		t.Fatal("Start after Close must fail")
	}
}
