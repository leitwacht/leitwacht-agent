//go:build linux

package enforcer

import (
	"log/slog"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// soNetnsCookie is Linux's SO_NETNS_COOKIE sockopt (added in 5.14). The
// x/sys/unix package exports this as unix.SO_NETNS_COOKIE; defined
// locally to remain tolerant of older x/sys/unix versions that predate
// the constant.
const soNetnsCookie = 71

// netnsCookieFromConn returns the netns cookie of the netns that conn's
// underlying socket lives in. Works for any syscall.Conn-capable type
// (*net.UDPConn, *net.TCPListener, etc.).
//
// Returns 0 on any failure: kernel pre-5.14 without the sockopt, a non-
// syscall-Conn type (test mocks), or a platform without SO_NETNS_COOKIE.
// Callers treat zero as "unknown netns" — the BPF side keys on the
// kernel-observed cookie, so a zero userspace cookie just misses every
// lookup. Degrades to no-attribution, never to wrong attribution.
func netnsCookieFromConn(conn net.PacketConn, logger *slog.Logger) uint64 {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0
	}

	raw, err := sc.SyscallConn()
	if err != nil {
		if logger != nil {
			logger.Debug("dns proxy: netns cookie SyscallConn failed", "error", err)
		}

		return 0
	}

	var (
		cookie  uint64
		sockErr error
	)

	err = raw.Control(func(fd uintptr) {
		// fd comes from net.PacketConn.SyscallConn().Control which
		// provides a Linux file descriptor (int range). The conversion
		// is safe and gosec's G115 warning is a false positive here.
		cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, soNetnsCookie) //nolint:gosec // fd fits int
	})
	if err != nil || sockErr != nil {
		if logger != nil {
			logger.Debug("dns proxy: getsockopt(SO_NETNS_COOKIE) failed",
				"control_err", err, "sockopt_err", sockErr)
		}

		return 0
	}

	return cookie
}
