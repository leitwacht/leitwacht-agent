//go:build linux

package enforcer

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// credwatchTestEnv loads credwatch with the given watched suffixes and
// puts the test process's own cgroup under watch with the given flags.
// It returns a function that returns the events seen so far.
func credwatchTestEnv(t *testing.T, watched []string, allow, observeOnly bool) (*credwatchObjects, func() []credwatchEventBPF) {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	objs, lsmLink, err := loadCredwatchLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}

	t.Cleanup(func() { objs.Close() })    //nolint:errcheck // test cleanup
	t.Cleanup(func() { lsmLink.Close() }) //nolint:errcheck // test cleanup

	pathLinks := attachCredwatchPathHooks(objs, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if len(pathLinks) != 2 {
		t.Skipf("path_rename/path_link hooks not available on this kernel (%d attached)", len(pathLinks))
	}

	t.Cleanup(func() {
		for _, l := range pathLinks {
			l.Close() //nolint:errcheck,gosec // test cleanup
		}
	})

	if err = populateWatchedPathMaps(objs, watched, nil); err != nil {
		t.Fatalf("populateWatchedPathMaps: %v", err)
	}

	var (
		mu     sync.Mutex
		events []credwatchEventBPF
	)

	stop, err := startCredwatchReader(objs, slog.New(slog.NewTextHandler(os.Stderr, nil)), func(e credwatchEventBPF) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("startCredwatchReader: %v", err)
	}

	t.Cleanup(stop)

	cgPath, err := getCgroupPath(os.Getpid())
	if err != nil {
		t.Fatalf("get cgroup path: %v", err)
	}

	var st syscall.Stat_t
	if err = syscall.Stat(cgPath, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	// Registered last so it runs first: stop watching before temp dirs
	// are removed.
	t.Cleanup(func() { removeCredwatchMaps(objs, st.Ino) })

	setWatch := func() {
		if err = populateCredwatchMaps(objs, st.Ino, allow, observeOnly); err != nil {
			t.Fatalf("populateCredwatchMaps: %v", err)
		}
	}
	setWatch()

	return objs, func() []credwatchEventBPF {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()

		return append([]credwatchEventBPF(nil), events...)
	}
}

// mustWrite creates a file (and parents). Callers use names outside
// watched_filenames so the create itself is not denied.
func mustWrite(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestCredwatchRenameAndLinkDenied(t *testing.T) {
	_, events := credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	dir := t.TempDir()

	// Create under a non-watched name, then rename to the watched name
	// (renaming TO a watched name is fine; only the source name matters).
	mustWrite(t, filepath.Join(dir, ".testcred", "stage"))

	if err := os.Rename(filepath.Join(dir, ".testcred", "stage"), filepath.Join(dir, ".testcred", "secret")); err != nil {
		t.Fatalf("rename to watched name must be allowed: %v", err)
	}

	src := filepath.Join(dir, ".testcred", "secret")

	if err := os.Rename(src, filepath.Join(dir, "moved")); !os.IsPermission(err) && !isEPERM(err) {
		t.Fatalf("rename of watched file: want EPERM, got %v", err)
	}

	if err := os.Link(src, filepath.Join(dir, "hardlink")); !isEPERM(err) {
		t.Fatalf("hardlink of watched file: want EPERM, got %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "moved")); err == nil {
		t.Fatal("rename was not blocked")
	}

	found := 0

	for _, e := range events() {
		if nullTerminated(e.Path[:]) == "secret" {
			found++
		}
	}

	if found < 2 {
		t.Fatalf("expected report events for rename and link, got %d", found)
	}
}

func TestCredwatchRenameLinkObserveOnlyAllowed(t *testing.T) {
	_, events := credwatchTestEnv(t, []string{"/.testcred/secret"}, false, true)

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".testcred", "stage"))

	src := filepath.Join(dir, ".testcred", "secret")
	if err := os.Rename(filepath.Join(dir, ".testcred", "stage"), src); err != nil {
		t.Fatalf("rename: %v", err)
	}

	if err := os.Link(src, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatalf("observe-only must allow link: %v", err)
	}

	if len(events()) == 0 {
		t.Fatal("observe-only must still report")
	}
}

// A path too long for the 128-byte d_path buffer used to fail open.
func TestCredwatchLongPathFailsClosed(t *testing.T) {
	_, events := credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	dir := t.TempDir()
	long := filepath.Join(dir, strings.Repeat("d", 60), strings.Repeat("e", 60), ".testcred", "secret")
	mustWrite(t, filepath.Join(filepath.Dir(long), "stage"))

	if err := os.Rename(filepath.Join(filepath.Dir(long), "stage"), long); err != nil {
		t.Fatalf("rename: %v", err)
	}

	if len(long) < 128 {
		t.Fatalf("test path too short (%d) to exceed the d_path buffer", len(long))
	}

	f, err := os.Open(long)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if !isEPERM(err) {
		t.Fatalf("open of watched name behind an over-long path: want EPERM, got %v", err)
	}

	if len(events()) == 0 {
		t.Fatal("fail-closed open must be reported")
	}
}

// An absolute watched suffix matches a path equal to the suffix (pos 0).
func TestCredwatchSuffixMatchesAtPositionZero(t *testing.T) {
	// d_path yields the symlink-resolved path, so watch exactly that: the
	// whole path equals the suffix, which only matches at position 0.
	target, evalErr := filepath.EvalSymlinks("/etc/os-release")
	if evalErr != nil || len(target) >= 64 {
		t.Skip("no usable /etc/os-release")
	}

	credwatchTestEnv(t, []string{target}, false, false)

	f, err := os.Open(target)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if !isEPERM(err) {
		t.Fatalf("open %s: want EPERM, got %v", target, err)
	}
}

func isEPERM(err error) bool {
	return err != nil && strings.Contains(err.Error(), "operation not permitted")
}
