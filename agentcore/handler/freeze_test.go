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
	"syscall"
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
	f := &Freezer{Logger: quietLogger(), StateDir: t.TempDir(), CgroupRoot: "/"}

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
	f := &Freezer{Logger: quietLogger(), StateDir: t.TempDir(), CgroupRoot: "/"}

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
	if _, err := (&Freezer{Logger: quietLogger(), StateDir: t.TempDir(), CgroupRoot: "/"}).Freeze(context.Background(), "c1", dir, time.Second); !errors.Is(err, ErrFreezeUnavailable) {
		t.Fatalf("err = %v, want ErrFreezeUnavailable", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "cgroup.freeze")); err == nil {
		t.Fatal("Freeze must not create cgroup.freeze")
	}

	p := &fakePauser{}
	f := &Freezer{Logger: quietLogger(), Pauser: p, StateDir: t.TempDir(), CgroupRoot: "/"}

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
	f := &Freezer{Logger: quietLogger(), StateDir: t.TempDir(), CgroupRoot: "/"}

	_, err := f.Freeze(context.Background(), "c1", filepath.Join(t.TempDir(), "gone"), time.Second)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}

func TestFreezeHardLimitThaws(t *testing.T) {
	dir := fakeCgroup(t, true)
	f := &Freezer{Logger: quietLogger(), HoldLimit: 30 * time.Millisecond, StateDir: t.TempDir(), CgroupRoot: "/"}

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
	f := &Freezer{Logger: quietLogger(), StateDir: t.TempDir(), CgroupRoot: "/"}
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

// TestRecoverFrozenThawsAfterProcessDeath simulates the agent dying between
// Freeze and Thaw: the marker is left behind, a fresh Freezer on the same
// state dir (the restarted agent) thaws the cgroup and clears the marker.
func TestRecoverFrozenThawsAfterProcessDeath(t *testing.T) {
	dir := fakeCgroup(t, true)
	state := t.TempDir()

	dying := &Freezer{Logger: quietLogger(), StateDir: state, CgroupRoot: "/"}
	if _, err := dying.Freeze(context.Background(), "c1", dir, time.Second); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	// No Thaw, no ThawAll: the process "died". The marker must exist.
	if entries, _ := os.ReadDir(state); len(entries) != 1 {
		t.Fatalf("expected one freeze marker, got %d", len(entries))
	}

	if got := readFreezeFile(t, dir); got != "1" {
		t.Fatalf("cgroup.freeze = %q, want held", got)
	}

	restarted := &Freezer{Logger: quietLogger(), StateDir: state, CgroupRoot: "/"}
	if n := restarted.RecoverFrozen(context.Background()); n != 1 {
		t.Fatalf("RecoverFrozen processed %d markers, want 1", n)
	}

	if got := readFreezeFile(t, dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after recovery, want 0", got)
	}

	if entries, _ := os.ReadDir(state); len(entries) != 0 {
		t.Fatalf("markers left after recovery: %d", len(entries))
	}
}

func TestRecoverFrozenUnpausesAndSkipsGoneCgroups(t *testing.T) {
	state := t.TempDir()
	p := &fakePauser{}

	dying := &Freezer{Logger: quietLogger(), StateDir: state, CgroupRoot: "/", Pauser: p}
	if _, err := dying.Freeze(context.Background(), "ctr-paused", "", time.Second); err != nil {
		t.Fatalf("pause: %v", err)
	}

	gone := fakeCgroup(t, true)
	if _, err := dying.Freeze(context.Background(), "ctr-gone", gone, time.Second); err != nil {
		t.Fatalf("freeze: %v", err)
	}

	_ = os.RemoveAll(gone) // container exited while the agent was down

	p2 := &fakePauser{}
	if n := (&Freezer{Logger: quietLogger(), StateDir: state, CgroupRoot: "/", Pauser: p2}).RecoverFrozen(context.Background()); n != 2 {
		t.Fatalf("processed %d markers, want 2", n)
	}

	if len(p2.unpaused) != 1 || p2.unpaused[0] != "ctr-paused" {
		t.Fatalf("unpaused = %v, want [ctr-paused]", p2.unpaused)
	}
}

func TestHardLimitKillsWhenFlagged(t *testing.T) {
	dir := fakeCgroup(t, true)

	killed := make(chan string, 1)
	f := &Freezer{
		Logger: quietLogger(), StateDir: t.TempDir(), CgroupRoot: "/", HoldLimit: 20 * time.Millisecond,
		Kill: func(id, scope string) { killed <- id + "|" + scope },
	}

	z, err := f.Freeze(context.Background(), "c1", dir, time.Second)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	z.SetKillOnExpire(true)

	select {
	case got := <-killed:
		if got != "c1|"+dir {
			t.Fatalf("kill called with %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hard limit did not kill a block-mode freeze")
	}

	deadline := time.Now().Add(time.Second)
	for readFreezeFile(t, dir) != "0" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if got := readFreezeFile(t, dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after expiry, want thawed", got)
	}
}

func TestRecoverFrozenRejectsMarkerOutsideCgroupMount(t *testing.T) {
	state := t.TempDir()
	victim := t.TempDir()
	writeFile(t, filepath.Join(victim, "cgroup.freeze"), "1")

	for i, path := range []string{victim, "/sys/fs/cgroup/../" + victim} {
		writeFile(t, filepath.Join(state, "m"+string(rune('a'+i))), "cgroup "+path+"\n")
	}

	// Default CgroupRoot (/sys/fs/cgroup): neither path qualifies.
	(&Freezer{Logger: quietLogger(), StateDir: state}).RecoverFrozen(context.Background())

	if got := readFreezeFile(t, victim); got != "1" {
		t.Fatalf("recovery wrote to a path outside the cgroup mount (cgroup.freeze = %q)", got)
	}
}

func TestThawFailureKeepsMarker(t *testing.T) {
	dir := fakeCgroup(t, true)
	state := t.TempDir()
	f := &Freezer{Logger: quietLogger(), StateDir: state, CgroupRoot: "/"}

	z, err := f.Freeze(context.Background(), "c1", dir, time.Second)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	// Make the thaw write fail with something other than ENOENT: replace
	// cgroup.freeze with a directory.
	_ = os.Remove(filepath.Join(dir, "cgroup.freeze"))
	_ = os.Mkdir(filepath.Join(dir, "cgroup.freeze"), 0o755)

	z.Thaw()

	if entries, _ := os.ReadDir(state); len(entries) != 1 {
		t.Fatalf("marker removed although the thaw failed (%d left)", len(entries))
	}
}

func TestIsFreezeDenied(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want bool
	}{
		{syscall.EROFS, true},
		{syscall.EACCES, true},
		{syscall.EPERM, true},
		{&os.PathError{Op: "open", Path: "x", Err: syscall.EROFS}, true},
		{syscall.ENOENT, false},
		{syscall.EBUSY, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isFreezeDenied(c.err); got != c.want {
			t.Errorf("isFreezeDenied(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestFreezeCgroupPermissionDeniedIsUnavailable(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "cgroup.freeze")

	if err := os.WriteFile(f, nil, 0o444); err != nil {
		t.Fatal(err)
	}

	_, err := freezeCgroup(context.Background(), dir, time.Second)
	if !errors.Is(err, ErrFreezeUnavailable) {
		t.Fatalf("want ErrFreezeUnavailable, got %v", err)
	}
}
