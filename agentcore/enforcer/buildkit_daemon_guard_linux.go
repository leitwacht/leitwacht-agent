//go:build linux

package enforcer

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// fileID identifies a file by device and inode.
type fileID struct{ dev, ino uint64 }

// statID stats a path in the agent's own view.
func statID(path string) (fileID, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, false
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}

	return fileID{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert,gosec // Dev width differs per arch
}

// openat2Fn is swapped in tests.
var openat2Fn = unix.Openat2

// openat2Unavailable is set when openat2(RESOLVE_IN_ROOT) is not usable
// (ENOSYS or blocked by seccomp). The unix tie then fails closed.
var openat2Unavailable atomic.Bool

// statInRoot resolves path inside root as if root were "/": absolute
// symlinks and ".." never escape it, so a pod cannot point the lookup at a
// file in the agent's own filesystem. It uses openat2(RESOLVE_IN_ROOT) and
// fails closed (no match) where that is unavailable: a userspace walk
// would race with the pod rewriting links.
func statInRoot(root, path string) (fileID, bool) {
	rootFd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fileID{}, false
	}
	defer unix.Close(rootFd) //nolint:errcheck // best effort

	rel := strings.TrimLeft(path, "/")
	if rel == "" {
		rel = "."
	}

	fd, err := openat2Fn(rootFd, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
			openat2Unavailable.Store(true)
		}

		return fileID{}, false
	}
	defer unix.Close(fd) //nolint:errcheck // best effort

	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return fileID{}, false
	}

	return fileID{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert,gosec // width differs per arch
}
