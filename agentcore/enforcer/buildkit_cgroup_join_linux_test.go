//go:build linux

package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func startInotify(t *testing.T, src *InotifyCgroupSource) (chan CgroupCreateEvent, chan CgroupRemoveEvent, func() error) {
	t.Helper()

	creates := make(chan CgroupCreateEvent, 16)
	removes := make(chan CgroupRemoveEvent, 16)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)

	go func() { errc <- src.Run(ctx, creates, removes) }()

	var stopped bool

	stop := func() error {
		if stopped {
			return nil
		}

		stopped = true

		cancel()

		select {
		case err := <-errc:
			return err
		case <-time.After(3 * time.Second):
			t.Fatal("Run did not return after cancel")

			return nil
		}
	}

	t.Cleanup(func() { _ = stop() })

	return creates, removes, stop
}

func TestInotifyCgroupSource_CreateRemoveAndCancel(t *testing.T) {
	dir := t.TempDir()
	creates, removes, stop := startInotify(t, NewInotifyCgroupSource([]string{dir}))

	// Give the watch a moment to be installed before creating.
	time.Sleep(50 * time.Millisecond)

	child := filepath.Join(dir, "ctr-1")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-creates:
		if ev.ContainerID != "ctr-1" || ev.CgroupPath != child {
			t.Fatalf("create event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no create event")
	}

	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-removes:
		if ev.ContainerID != "ctr-1" {
			t.Fatalf("remove event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no remove event")
	}

	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}

	// Channels are closed on exit.
	if _, ok := <-creates; ok {
		t.Error("creates channel not closed")
	}
}

// An idle watch must block, not spin: CPU time over an idle window
// stays far below the window.
func TestInotifyCgroupSource_IdleDoesNotSpin(t *testing.T) {
	dir := t.TempDir()
	_, _, stop := startInotify(t, NewInotifyCgroupSource([]string{dir}))

	var before, after cpuTimes

	before.read(t)
	time.Sleep(500 * time.Millisecond)
	after.read(t)

	if used := after.total() - before.total(); used > 150*time.Millisecond {
		t.Fatalf("idle inotify loop burned %s CPU in 500ms", used)
	}

	_ = stop()
}

func TestInotifyCgroupSource_RewatchesAfterWatchedDirRemoved(t *testing.T) {
	parent := t.TempDir()
	watched := filepath.Join(parent, "buildkit")

	if err := os.Mkdir(watched, 0o755); err != nil {
		t.Fatal(err)
	}

	src := NewInotifyCgroupSource([]string{watched})
	src.rewatchEvery = 50 * time.Millisecond
	creates, _, _ := startInotify(t, src)

	time.Sleep(50 * time.Millisecond)

	// Delete and recreate the watched directory (IN_IGNORED on the old wd).
	if err := os.Remove(watched); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(watched, 0o755); err != nil {
		t.Fatal(err)
	}

	// A child already present when the watch is re-established is
	// reported by the rescan; one created later by the new watch.
	if err := os.Mkdir(filepath.Join(watched, "ctr-early"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	deadline := time.After(3 * time.Second)

	for !got["ctr-early"] {
		select {
		case ev := <-creates:
			got[ev.ContainerID] = true
		case <-deadline:
			t.Fatalf("no create for child after re-watch; got %v", got)
		}
	}

	time.Sleep(100 * time.Millisecond)

	if err := os.Mkdir(filepath.Join(watched, "ctr-late"), 0o755); err != nil {
		t.Fatal(err)
	}

	for !got["ctr-late"] {
		select {
		case ev := <-creates:
			got[ev.ContainerID] = true
		case <-deadline:
			t.Fatalf("new watch not delivering events; got %v", got)
		}
	}
}

func TestInotifyCgroupSource_NoPaths(t *testing.T) {
	creates := make(chan CgroupCreateEvent)
	removes := make(chan CgroupRemoveEvent)

	err := NewInotifyCgroupSource(nil).Run(context.Background(), creates, removes)
	if !errors.Is(err, ErrCgroupJoinUnsupported) {
		t.Fatalf("Run = %v, want ErrCgroupJoinUnsupported", err)
	}
}

func TestInotifyCgroupSource_BadPathReturnsAndCleansUp(t *testing.T) {
	creates := make(chan CgroupCreateEvent)
	removes := make(chan CgroupRemoveEvent)

	err := NewInotifyCgroupSource([]string{"/nonexistent-leitwacht-test"}).Run(context.Background(), creates, removes)
	if err == nil {
		t.Fatal("expected error for a missing watch path")
	}
}

// cpuTimes is this process's user+system CPU time.
type cpuTimes struct{ d time.Duration }

func (c *cpuTimes) read(t *testing.T) {
	t.Helper()

	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		t.Skipf("getrusage: %v", err)
	}

	c.d = time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func (c cpuTimes) total() time.Duration { return c.d }
