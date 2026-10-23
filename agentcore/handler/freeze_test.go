package handler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeCgroup creates a directory shaped like a cgroup v2 leaf: a writable
// cgroup.freeze and a cgroup.events the test controls.
func fakeCgroup(t *testing.T, frozen bool) string {
	t.Helper()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "cgroup.freeze"), "0")
	setFrozen(t, dir, frozen)

	return dir
}

func setFrozen(t *testing.T, dir string, frozen bool) {
	t.Helper()

	v := "0"
	if frozen {
		v = "1"
	}

	writeFile(t, filepath.Join(dir, "cgroup.events"), "populated 1\nfrozen "+v+"\n")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFreezeFile(t *testing.T, dir string) string {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(dir, "cgroup.freeze"))
	if err != nil {
		t.Fatalf("read cgroup.freeze: %v", err)
	}

	return strings.TrimSpace(string(b))
}

type fakePauser struct {
	mu       sync.Mutex
	paused   []string
	unpaused []string
}

func (p *fakePauser) PauseContainer(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.paused = append(p.paused, id)

	return nil
}

func (p *fakePauser) UnpauseContainer(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.unpaused = append(p.unpaused, id)

	return nil
}

func TestFreezeCgroupWaitsForFrozenThenThaws(t *testing.T) {
	dir := fakeCgroup(t, false)
	f := &Freezer{Logger: quietLogger()}

	// The kernel reports frozen a little after the write; the freezer must
	// poll rather than trust the write.
	done := make(chan struct{})

	go func() {
		defer close(done)

		time.Sleep(20 * time.Millisecond)
		setFrozen(t, dir, true)
	}()

	z, err := f.Freeze(context.Background(), "c1", dir, time.Second)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	<-done

	if got := readFreezeFile(t, dir); got != "1" {
		t.Fatalf("cgroup.freeze = %q while held, want 1", got)
	}

	z.Thaw()
	z.Thaw() // idempotent

	if got := readFreezeFile(t, dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after Thaw, want 0", got)
	}
}

func TestFreezeCgroupTimeoutReleasesContainer(t *testing.T) {
	dir := fakeCgroup(t, false) // never reports frozen
	f := &Freezer{Logger: quietLogger()}

	z, err := f.Freeze(context.Background(), "c1", dir, 30*time.Millisecond)
	if !errors.Is(err, ErrFreezeTimeout) {
		t.Fatalf("err = %v, want ErrFreezeTimeout", err)
	}

	if z != nil {
		t.Fatal("a failed freeze must not return a handle")
	}

	if got := readFreezeFile(t, dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after timeout, want 0 (never leave it frozen)", got)
	}
}

func TestFreezeUnavailableFallsBackToPause(t *testing.T) {
	dir := t.TempDir() // exists, but has no cgroup.freeze (cgroup v1 / old kernel)

	// Without a pauser: unavailable, nothing frozen.
	if _, err := (&Freezer{Logger: quietLogger()}).Freeze(context.Background(), "c1", dir, time.Second); !errors.Is(err, ErrFreezeUnavailable) {
		t.Fatalf("err = %v, want ErrFreezeUnavailable", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "cgroup.freeze")); err == nil {
		t.Fatal("Freeze must not create cgroup.freeze")
	}

	p := &fakePauser{}
	f := &Freezer{Logger: quietLogger(), Pauser: p}

	z, err := f.Freeze(context.Background(), "c1", dir, time.Second)
	if err != nil {
		t.Fatalf("Freeze with pauser: %v", err)
	}

	if len(p.paused) != 1 || p.paused[0] != "c1" {
		t.Fatalf("paused = %v, want [c1]", p.paused)
	}

	z.Thaw()

	if len(p.unpaused) != 1 {
		t.Fatalf("unpaused = %v, want one unpause", p.unpaused)
	}
}

func TestFreezeGoneCgroupIsNotExist(t *testing.T) {
	f := &Freezer{Logger: quietLogger()}

	_, err := f.Freeze(context.Background(), "c1", filepath.Join(t.TempDir(), "gone"), time.Second)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}

func TestFreezeHardLimitThaws(t *testing.T) {
	dir := fakeCgroup(t, true)
	f := &Freezer{Logger: quietLogger(), HoldLimit: 30 * time.Millisecond}

	z, err := f.Freeze(context.Background(), "c1", dir, time.Second)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	defer z.Thaw()

	deadline := time.Now().Add(2 * time.Second)
	for readFreezeFile(t, dir) != "0" {
		if time.Now().After(deadline) {
			t.Fatal("hard limit did not thaw the container")
		}

		time.Sleep(5 * time.Millisecond)
	}
}

func TestThawAllReleasesEverything(t *testing.T) {
	f := &Freezer{Logger: quietLogger()}
	dirs := []string{fakeCgroup(t, true), fakeCgroup(t, true)}

	for i, d := range dirs {
		if _, err := f.Freeze(context.Background(), "c"+string(rune('a'+i)), d, time.Second); err != nil {
			t.Fatalf("Freeze %d: %v", i, err)
		}
	}

	f.ThawAll()

	for _, d := range dirs {
		if got := readFreezeFile(t, d); got != "0" {
			t.Fatalf("cgroup.freeze = %q after ThawAll, want 0", got)
		}
	}
}
