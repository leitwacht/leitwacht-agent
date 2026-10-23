//go:build linux

package enforcer

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// mustWriteWatched creates a file that has a watched name: the create is
// done under a staging name and renamed into place (renaming TO a
// watched name is allowed), because creating it directly would be
// denied.
func mustWriteWatched(t *testing.T, path string) {
	t.Helper()

	stage := filepath.Join(filepath.Dir(path), "stage-tmp")
	mustWrite(t, stage)

	if err := os.Rename(stage, path); err != nil {
		t.Fatalf("rename into place: %v", err)
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

	if err := os.Rename(src, filepath.Join(dir, "moved")); !isEPERM(err) {
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

// deepDir returns a directory path under base whose total length is at
// least minLen, built from 120-char components.
func deepDir(base string, minLen int) string {
	d := base
	for len(d) < minLen {
		d = filepath.Join(d, strings.Repeat("d", 120))
	}

	return d
}

func openErr(path string) error {
	f, err := os.Open(path)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	return err
}

// Paths longer than the old 128-byte d_path buffer are resolved now:
// the suffix is matched on the tail, and unrelated files that merely
// share a watched name are not killed.
func TestCredwatchLongPath(t *testing.T) {
	_, events := credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	dir := t.TempDir()
	long := deepDir(dir, 300)

	hit := filepath.Join(long, ".testcred", "secret")
	mustWriteWatched(t, hit)

	if err := openErr(hit); !isEPERM(err) {
		t.Fatalf("long path + watched suffix: want EPERM, got %v", err)
	}

	if len(events()) == 0 {
		t.Fatal("long-path hit must be reported")
	}

	// Generic name, wrong parent: allowed.
	miss := filepath.Join(long, "other", "secret")
	mustWrite(t, miss)

	if err := openErr(miss); err != nil {
		t.Fatalf("long path + non-matching parent must be allowed, got %v", err)
	}
}

// A path beyond the 512-byte buffer makes d_path fail; the (parent,
// name) pair still decides.
func TestCredwatchDPathFailureUsesPair(t *testing.T) {
	_, events := credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	dir := t.TempDir()
	long := deepDir(dir, 700)

	hit := filepath.Join(long, ".testcred", "secret")
	mustWriteWatched(t, hit)

	if err := openErr(hit); !isEPERM(err) {
		t.Fatalf("unresolvable path + watched pair: want EPERM, got %v", err)
	}

	got := false

	for _, e := range events() {
		if e.Kind == credwatchKindDPathFail {
			got = true
		}
	}

	if !got {
		t.Fatal("expected a dpath_fail event")
	}

	miss := filepath.Join(long, "other", "secret")
	mustWrite(t, miss)

	if err := openErr(miss); err != nil {
		t.Fatalf("unresolvable path + unrelated parent must be allowed, got %v", err)
	}
}

// Rename/link restrict to the watched (parent, name) pair and to regular
// files: a same-named file elsewhere is untouched.
func TestCredwatchRenameLinkIgnoreUnrelated(t *testing.T) {
	credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	dir := t.TempDir()
	other := filepath.Join(dir, "work", "secret")
	mustWrite(t, other)

	if err := os.Link(other, filepath.Join(dir, "work", "l")); err != nil {
		t.Fatalf("link of unrelated same-named file: %v", err)
	}

	if err := os.Rename(other, filepath.Join(dir, "work", "moved")); err != nil {
		t.Fatalf("rename of unrelated same-named file: %v", err)
	}
}

func TestCredwatchRenameExchangeDenied(t *testing.T) {
	credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	dir := t.TempDir()
	cred := filepath.Join(dir, ".testcred", "secret")
	plain := filepath.Join(dir, "plain")
	mustWriteWatched(t, cred)
	mustWrite(t, plain)

	err := unix.Renameat2(unix.AT_FDCWD, plain, unix.AT_FDCWD, cred, unix.RENAME_EXCHANGE)
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("RENAME_EXCHANGE onto a watched file: want EPERM, got %v", err)
	}
}

func TestCredwatchDirectoryRename(t *testing.T) {
	credwatchTestEnv(t, []string{"/.testcred/secret", "/secrets/tok", "/rancher/k3s/k3s.yaml"}, false, false)

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".testcred", "x"))
	mustWrite(t, filepath.Join(dir, "secrets", "x"))
	mustWrite(t, filepath.Join(dir, "rancher", "k3s", "x"))
	mustWrite(t, filepath.Join(dir, "unrelated", "k3s", "x"))

	if err := os.Rename(filepath.Join(dir, ".testcred"), filepath.Join(dir, "gone")); !isEPERM(err) {
		t.Fatalf("rename of a credentials directory: want EPERM, got %v", err)
	}

	// "secrets" has no grandparent in its suffix and is generic: not protected.
	if err := os.Rename(filepath.Join(dir, "secrets"), filepath.Join(dir, "renamed")); err != nil {
		t.Fatalf("rename of generic directory must be allowed: %v", err)
	}

	// rancher/k3s is a watched (grandparent, dir) pair; k3s elsewhere is not.
	if err := os.Rename(filepath.Join(dir, "rancher", "k3s"), filepath.Join(dir, "rancher", "k3s-old")); !isEPERM(err) {
		t.Fatalf("rename of rancher/k3s: want EPERM, got %v", err)
	}

	if err := os.Rename(filepath.Join(dir, "unrelated", "k3s"), filepath.Join(dir, "unrelated", "k3s-old")); err != nil {
		t.Fatalf("rename of an unrelated k3s directory must be allowed: %v", err)
	}
}

// Excluded suffixes are not acted on by any hook.
func TestCredwatchExclusionHonouredByRenameLink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	objs, _ := credwatchTestEnv(t, []string{"/.testcred/secret"}, false, false)

	// Re-populate: add an excluded second suffix.
	if err := populateWatchedPathMaps(objs, []string{"/.keep/secret", "/.testcred/secret"}, []string{"/.keep/secret"}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	keep := filepath.Join(dir, ".keep", "secret")
	mustWriteWatched(t, keep)

	if err := os.Rename(keep, filepath.Join(dir, ".keep", "moved")); err != nil {
		t.Fatalf("rename of excluded suffix must be allowed: %v", err)
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
