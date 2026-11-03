//go:build linux

package enforcer

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeProcRoot writes <root>/<pid>/root/etc/resolv.conf.
func fakeProcRoot(t *testing.T, files map[int]string) string {
	t.Helper()

	root := t.TempDir()

	for pid, content := range files {
		dir := filepath.Join(root, strconv.Itoa(pid), "root", "etc")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func TestReadSearchList(t *testing.T) {
	root := fakeProcRoot(t, map[int]string{
		100: "search team.svc.cluster.local svc.cluster.local\noptions ndots:5\n",
		200: "domain corp.test\n",
		300: "nameserver 1.1.1.1\n",
	})

	cases := []struct {
		pid  int
		want []string
	}{
		{100, []string{"team.svc.cluster.local", "svc.cluster.local"}},
		{200, []string{"corp.test"}}, // a different container's file differs from the pod's
		{300, nil},                   // no search line: no suppression
		{999, nil},                   // missing file / process: no suppression
	}

	for _, tc := range cases {
		if got := readSearchList(root, tc.pid); !reflect.DeepEqual(got, tc.want) && (len(got) != 0 || len(tc.want) != 0) {
			t.Errorf("pid %d: got %v, want %v", tc.pid, got, tc.want)
		}
	}
}

func TestReadSearchList_SymlinkEscapeAndNonRegular(t *testing.T) {
	root := t.TempDir()

	// A host-side file the container must not be able to point us at.
	hostFile := filepath.Join(root, "host-resolv.conf")
	if err := os.WriteFile(hostFile, []byte("search host.secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	etc := filepath.Join(root, "1", "root", "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}

	// Final component is a symlink: refused (O_NOFOLLOW).
	if err := os.Symlink(hostFile, filepath.Join(etc, "resolv.conf")); err != nil {
		t.Fatal(err)
	}

	if got := readSearchList(root, 1); got != nil {
		t.Fatalf("symlinked resolv.conf must not be read, got %v", got)
	}

	// Directory symlink with an absolute target resolves inside the
	// container root (RESOLVE_IN_ROOT), not on the host.
	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, "2", "root"), 0o755); err != nil {
		t.Fatal(err)
	}

	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "resolv.conf"), []byte("search host.secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(hostDir, filepath.Join(root2, "2", "root", "etc")); err != nil {
		t.Fatal(err)
	}

	if got := readSearchList(root2, 2); got != nil {
		t.Fatalf("absolute dir symlink escaped the container root: %v", got)
	}
}

func TestRegisterSearchList(t *testing.T) {
	root := fakeProcRoot(t, map[int]string{
		10: "search a.test b.test\n",
		20: "search c.test\n",
	})

	m := &Manager{procRoot: root, logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	nctx := &NetnsContext{}

	m.registerSearchList(nctx, []uint64{1, 11}, 10)
	m.registerSearchList(nctx, []uint64{2}, 20)
	m.registerSearchList(nctx, []uint64{3}, 999) // unreadable: nothing registered

	checks := map[uint64][]string{
		1:  {"a.test", "b.test"},
		11: {"a.test", "b.test"}, // leaf cgroup of the same container
		2:  {"c.test"},
		3:  nil,
		42: nil,                  // unknown non-zero cgroup: no suppression
		0:  {"a.test", "b.test"}, // unattributed: first snapshot
	}

	for id, want := range checks {
		if got := nctx.searchListFor(id); !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
			t.Errorf("cgroup %d: got %v, want %v", id, got, want)
		}
	}
}

func TestReadSearchList_NonRegularFiles(t *testing.T) {
	root := t.TempDir()

	mk := func(pid string) string {
		dir := filepath.Join(root, pid, "root", "etc")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		return filepath.Join(dir, "resolv.conf")
	}

	if err := unix.Mkfifo(mk("1"), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan []string, 1)

	go func() { done <- readSearchList(root, 1) }()

	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("FIFO must yield nil, got %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readSearchList blocked on a FIFO")
	}

	// A directory in place of the file.
	if err := os.Mkdir(mk("2"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := readSearchList(root, 2); got != nil {
		t.Fatalf("directory must yield nil, got %v", got)
	}

	// Character device: needs CAP_MKNOD, unavailable to an unprivileged test run.
	if err := unix.Mknod(mk("3"), unix.S_IFCHR|0o644, int(unix.Mkdev(1, 3))); err != nil {
		t.Skipf("cannot create a character device without CAP_MKNOD: %v", err)
	}

	if got := readSearchList(root, 3); got != nil {
		t.Fatalf("char device must yield nil, got %v", got)
	}
}
