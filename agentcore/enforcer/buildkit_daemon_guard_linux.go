//go:build linux

package enforcer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// statInRoot resolves path inside root as if root were "/": absolute
// symlinks and ".." never escape it, so a pod cannot point the lookup at a
// file in the agent's own filesystem. It uses openat2(RESOLVE_IN_ROOT) and
// falls back to a manual in-root walk where that is unavailable.
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

	fd, err := unix.Openat2(rootFd, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err == nil {
		defer unix.Close(fd) //nolint:errcheck // best effort

		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return fileID{}, false
		}

		return fileID{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert,gosec // width differs per arch
	}

	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
		return fileID{}, false
	}

	return walkInRoot(root, path)
}

// walkInRoot is the manual in-root resolution used when openat2 is
// unavailable. Every symlink is resolved by hand against root.
func walkInRoot(root, path string) (fileID, bool) {
	const maxLinks = 40

	var stack []string // resolved components below root

	todo := splitPath(path)
	links := 0

	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]

		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

			continue
		}

		cur := filepath.Join(append([]string{root}, append(stack, c)...)...)

		fi, err := os.Lstat(cur)
		if err != nil {
			return fileID{}, false
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			stack = append(stack, c)

			continue
		}

		if links++; links > maxLinks {
			return fileID{}, false
		}

		target, err := os.Readlink(cur)
		if err != nil {
			return fileID{}, false
		}

		if strings.HasPrefix(target, "/") {
			stack = nil
		}

		todo = append(splitPath(target), todo...)
	}

	return statID(filepath.Join(append([]string{root}, stack...)...))
}

func splitPath(p string) []string { return strings.Split(p, "/") }
