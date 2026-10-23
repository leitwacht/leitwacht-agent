//go:build linux && integration

package enforcer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	guardResolverIP   = "127.0.0.11"
	guardResolverPort = 40053 // where the Docker-shaped DNAT sends :53
)

// TestIntegrationEmbeddedResolverGuard installs the real DNS redirect rules
// in a throwaway netns, next to a Docker-shaped `ip nat OUTPUT` DNAT
// (127.0.0.11:53 -> 127.0.0.11:40053), and checks with real UDP and TCP
// sockets that:
//   - unmarked traffic to 127.0.0.11 on a non-53 port is dropped, marked
//     traffic is delivered;
//   - unmarked port-53 lookups reach the proxy (127.0.0.1:15353), ahead of
//     Docker's own DNAT, for UDP and TCP;
//   - marked port-53 traffic reaches the resolver and its genuine reply comes
//     back (the reply-direction packet must survive the guard), UDP and TCP;
//   - a forged reply — sent from a socket the job bound to 127.0.0.11:53 to
//     the proxy's marked upstream socket's local address — is never delivered.
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

func addDockerShapedDNAT(conn *nftables.Conn) {
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "nat"})
	chain := conn.AddChain(&nftables.Chain{
		Name: "OUTPUT", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest,
	})

	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dockerResolverIP},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x35}},
			&expr.Immediate{Register: 1, Data: dockerResolverIP},
			&expr.Immediate{Register: 2, Data: []byte{byte(guardResolverPort >> 8), byte(guardResolverPort & 0xff)}},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
		}})
	}
}

func setMark(c syscallConner, mark int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error

	if ctlErr := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
	}); ctlErr != nil {
		return ctlErr
	}

	return sockErr
}

type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

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

	addDockerShapedDNAT(conn)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("docker-shaped dnat: %w", err)
	}

	if err := setupDNSRedirect(conn); err != nil {
		return err
	}

	// Docker's embedded resolver stand-in: UDP+TCP on 127.0.0.11:40053,
	// answering every request with "r".
	dockerUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(guardResolverIP), Port: guardResolverPort})
	if err != nil {
		return err
	}
	defer dockerUDP.Close()

	go func() {
		buf := make([]byte, 64)

		for {
			_, from, readErr := dockerUDP.ReadFromUDP(buf)
			if readErr != nil {
				return
			}

			_, _ = dockerUDP.WriteToUDP([]byte("r"), from)
		}
	}()

	dockerTCP, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(guardResolverIP), Port: guardResolverPort})
	if err != nil {
		return err
	}
	defer dockerTCP.Close()

	go func() {
		for {
			c, acceptErr := dockerTCP.Accept()
			if acceptErr != nil {
				return
			}

			_, _ = c.Write([]byte("r"))
			_ = c.Close()
		}
	}()

	// The proxy stand-in on 127.0.0.1:15353 (records receipt only).
	proxyUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyListenPort})
	if err != nil {
		return err
	}
	defer proxyUDP.Close()

	proxyTCP, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyListenPort})
	if err != nil {
		return err
	}
	defer proxyTCP.Close()

	udpDial := func(dst string, mark int) (*net.UDPConn, error) {
		a, _ := net.ResolveUDPAddr("udp4", dst)
		c, dialErr := net.DialUDP("udp4", nil, a)
		if dialErr != nil {
			return nil, dialErr
		}

		if mark != 0 {
			if mErr := setMark(c, mark); mErr != nil {
				c.Close()

				return nil, mErr
			}
		}

		return c, nil
	}

	// A local output-hook drop surfaces as EPERM on write; either that or
	// silence means "dropped".
	udpSend := func(c *net.UDPConn) error {
		_, werr := c.Write([]byte("q"))
		if werr != nil && !errors.Is(werr, unix.EPERM) {
			return werr
		}

		return nil
	}

	udpRecv := func(c *net.UDPConn) bool {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, rerr := c.Read(make([]byte, 16))

		return rerr == nil
	}

	// The production dialer, holding this (throwaway) netns open.
	nsHandle, err := netns.Get()
	if err != nil {
		return err
	}

	dialer := &netnsDialer{handle: nsHandle}
	defer dialer.Close()

	// 1. Unmarked UDP to the resolver's high port: dropped. Marked: delivered.
	c, err := udpDial(fmt.Sprintf("%s:%d", guardResolverIP, guardResolverPort), 0)
	if err != nil {
		return err
	}

	if err := udpSend(c); err != nil {
		return err
	}

	if udpRecv(c) {
		t.Error("unmarked UDP to the embedded resolver high port got a reply")
	}

	c.Close()

	c, err = udpDial(fmt.Sprintf("%s:%d", guardResolverIP, guardResolverPort), agentMark)
	if err != nil {
		return err
	}

	if err := udpSend(c); err != nil {
		return err
	}

	if !udpRecv(c) {
		t.Error("marked UDP to the embedded resolver high port was dropped")
	}

	c.Close()

	// 2. Unmarked UDP :53 reaches the proxy, not Docker's DNAT target.
	c, err = udpDial(guardResolverIP+":53", 0)
	if err != nil {
		return err
	}

	if err := udpSend(c); err != nil {
		return err
	}

	_ = proxyUDP.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	if _, _, rerr := proxyUDP.ReadFromUDP(make([]byte, 16)); rerr != nil {
		t.Error("unmarked UDP :53 was not redirected to the proxy")
	}

	c.Close()

	// 3. Marked UDP :53 -> DNAT -> resolver; its genuine reply returns.
	marked, err := dialer.DialUDP(guardResolverIP+":53", agentMark)
	if err != nil {
		return err
	}
	defer marked.Close()

	if err := udpSend(marked); err != nil {
		return err
	}

	if !udpRecv(marked) {
		t.Error("marked UDP :53: genuine resolver reply did not come back through the guard")
	}

	// 4. Forgery. The job binds 127.0.0.11:53 and fires datagrams at the
	// proxy's marked upstream socket's local address BEFORE the real query
	// (once the query's conntrack entry exists the kernel's own clash
	// handling swallows them, so only the pre-send matters). Nothing may
	// arrive.
	victim, err := dialer.DialUDP(guardResolverIP+":53", agentMark)
	if err != nil {
		return err
	}
	defer victim.Close()

	forger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(guardResolverIP), Port: 53})
	if err != nil {
		return err
	}
	defer forger.Close()

	target := victim.LocalAddr().(*net.UDPAddr)

	for range 5 {
		_, werr := forger.WriteToUDP([]byte("forged"), target)
		if werr != nil && !errors.Is(werr, unix.EPERM) {
			return werr
		}
	}

	if udpRecv(victim) {
		t.Error("forged reply from 127.0.0.11:53 was delivered to the proxy's upstream socket")
	}

	// 5. TCP: unmarked :53 -> proxy; marked :53 -> resolver with data back.
	tc, err := net.DialTimeout("tcp4", guardResolverIP+":53", time.Second)
	if err != nil {
		t.Errorf("unmarked TCP :53 connect failed: %v", err)
	} else {
		_ = proxyTCP.SetDeadline(time.Now().Add(500 * time.Millisecond))

		if pc, aerr := proxyTCP.Accept(); aerr != nil {
			t.Error("unmarked TCP :53 was not redirected to the proxy")
		} else {
			pc.Close()
		}

		tc.Close()
	}

	mc, err := dialer.DialTCP(guardResolverIP+":53", agentMark)
	if err != nil {
		t.Errorf("marked TCP :53 connect failed: %v", err)
	} else {
		_ = mc.SetReadDeadline(time.Now().Add(time.Second))

		if b, rerr := io.ReadAll(mc); rerr != nil || string(b) != "r" {
			t.Errorf("marked TCP :53: reply = %q, err = %v", b, rerr)
		}

		mc.Close()
	}

	// 6. Unmarked TCP to the high port: dropped.
	hc, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", guardResolverIP, guardResolverPort), 700*time.Millisecond)
	if err == nil {
		hc.Close()
		t.Error("unmarked TCP to the embedded resolver high port connected")
	}

	return nil
}
