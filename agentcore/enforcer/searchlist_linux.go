//go:build linux

package enforcer

import (
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// fuseSuperMagic is the statfs f_type of FUSE filesystems.
const fuseSuperMagic = 0x65735546

// readSearchList reads <procRoot>/<pid>/root/etc/resolv.conf and returns its
// search list. The lookup is confined to the container's root with
// openat2(RESOLVE_IN_ROOT), so symlinks inside the container cannot point at
// host files; the final component must be a regular file (no FIFO/device
// open can block the agent). Any failure yields nil (no suppression).
func readSearchList(procRoot string, pid int) []string {
	return readResolvConf(procRoot, pid).search
}

// readResolvConf is readSearchList's full form: it also yields ndots. Any
// failure yields the zero-value defaults (no search list, ndots 1, not
// explicit).
func readResolvConf(procRoot string, pid int) resolvConf {
	none := resolvConf{ndots: defaultNdots}

	rootFd, err := unix.Open(procRoot+"/"+strconv.Itoa(pid)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return none
	}
	defer unix.Close(rootFd) //nolint:errcheck // best-effort close of a read-only fd

	// Resolve without reading: O_PATH never triggers device or FIFO open
	// side effects, and lets us check the file type first.
	pathFd, err := unix.Openat2(rootFd, "etc/resolv.conf", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return none
	}
	defer unix.Close(pathFd) //nolint:errcheck // best-effort close of an O_PATH fd

	var st unix.Stat_t
	if unix.Fstat(pathFd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return none
	}

	// A FUSE server could stall a synchronous attach on read.
	var sfs unix.Statfs_t
	if unix.Fstatfs(pathFd, &sfs) != nil || sfs.Type == fuseSuperMagic {
		return none
	}

	// Reopen the very same inode (no path walk, so no TOCTOU).
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pathFd), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return none
	}

	f := os.NewFile(uintptr(fd), "resolv.conf")
	defer f.Close() //nolint:errcheck // read-only

	buf, err := io.ReadAll(io.LimitReader(f, maxResolvConfBytes))
	if err != nil && !errors.Is(err, io.EOF) {
		return none
	}

	return parseResolvConf(buf)
}
