//go:build linux && integration

package enforcer

import (
	"errors"
	"net"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// TestIntegrationEmbeddedResolverGuard installs the real DNS redirect rules
// in a throwaway netns and checks, with real sockets, that:
//   - an unmarked datagram to 127.0.0.11:<high port> is dropped,
//   - the same datagram carrying agentMark is delivered,
//   - an unmarked port-53 datagram to 127.0.0.11 is redirected to the proxy
//     port (127.0.0.1:15353), not dropped.
//
// Needs root (CAP_SYS_ADMIN for the netns, CAP_NET_ADMIN for SO_MARK/nft).
// It creates and discards its own netns; nothing else on the host is touched.
func TestIntegrationEmbeddedResolverGuard(t *testing.T) {
	result := make(chan error, 1)

	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with the goroutine, taking the netns with it

		result <- runGuardScenario(t)
	}()

	err := <-result

	var skip skipError
	if errors.As(err, &skip) {
		t.Skip(skip.Error())
	}

	if err != nil {
		t.Fatal(err)
	}
}

// skipError lets the scenario goroutine request a skip; t.Skip must run on
// the test goroutine.
type skipError string

func (s skipError) Error() string { return string(s) }

func runGuardScenario(t *testing.T) error {
	t.Helper()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return skipError("cannot create netns (need root): " + err.Error())
	}

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return skipError("ip link set lo up: " + err.Error() + " " + string(out))
	}

	conn, err := nftables.New()
	if err != nil {
		return err
	}

	if err := setupDNSRedirect(conn); err != nil {
		return err
	}

	resolver := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 11), Port: 40053}

	resolverSock, err := net.ListenUDP("udp4", resolver)
	if err != nil {
		return err
	}
	defer resolverSock.Close()

	proxySock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyListenPort})
	if err != nil {
		return err
	}
	defer proxySock.Close()

	send := func(dst *net.UDPAddr, mark int) error {
		c, dialErr := net.DialUDP("udp4", nil, dst)
		if dialErr != nil {
			return dialErr
		}
		defer c.Close()

		if mark != 0 {
			raw, rawErr := c.SyscallConn()
			if rawErr != nil {
				return rawErr
			}

			var sockErr error

			if ctlErr := raw.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			}); ctlErr != nil {
				return ctlErr
			}

			if sockErr != nil {
				return sockErr
			}
		}

		_, writeErr := c.Write([]byte("q"))

		return writeErr
	}

	got := func(s *net.UDPConn) bool {
		_ = s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		buf := make([]byte, 16)
		_, _, readErr := s.ReadFromUDP(buf)

		return readErr == nil
	}

	// A local output-hook drop surfaces as EPERM on write; either that or
	// silence means "dropped".
	if err := send(resolver, 0); err != nil && !errors.Is(err, unix.EPERM) {
		return err
	}

	if got(resolverSock) {
		t.Error("unmarked datagram to the embedded resolver high port was delivered")
	}

	if err := send(resolver, agentMark); err != nil {
		return err
	}

	if !got(resolverSock) {
		t.Error("agent-marked datagram to the embedded resolver was dropped")
	}

	if err := send(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 11), Port: 53}, 0); err != nil {
		return err
	}

	if !got(proxySock) {
		t.Error("unmarked port-53 datagram to 127.0.0.11 was not redirected to the proxy")
	}

	return nil
}
