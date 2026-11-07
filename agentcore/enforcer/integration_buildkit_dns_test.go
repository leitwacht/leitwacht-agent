//go:build linux && integration

package enforcer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

const (
	bkDNSHelperEnv = "LEITWACHT_BK_DNS_HELPER"
	// The "cluster DNS" the helper queries: an address nobody owns, so a
	// reply can only come from the redirect.
	bkDNSFakeResolver = "10.254.78.53:53"
)

// Helper exit codes.
const (
	bkHelperConnected   = 0
	bkHelperConnectFail = 1
	bkHelperResolveFail = 2
	bkHelperBadSource   = 4
)

// TestHelperBKResolveConnect is the workload: it resolves NAME through
// the fake cluster DNS (MODE=udp: an unconnected socket, checking the
// reply source is the address it asked; MODE=tcp), then connects to the
// first A answer on PORT. It prints "IP=<answer>" and exits with a
// bkHelper* code.
func TestHelperBKResolveConnect(t *testing.T) {
	name := os.Getenv(bkDNSHelperEnv)
	if name == "" {
		t.Skip("helper only")
	}

	port := os.Getenv("LEITWACHT_BK_DNS_PORT")
	mode := os.Getenv("LEITWACHT_BK_DNS_MODE")

	switch mode {
	case "v4mapped":
		// An AF_INET6 socket to a v4-mapped address skips connect4: the
		// packet leaves as IPv4 :53 and must be caught by the egress pin.
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		if err != nil {
			os.Exit(bkHelperResolveFail)
		}

		_ = syscall.SetNonblock(fd, true)

		sa := &syscall.SockaddrInet6{Port: 53}
		sa.Addr[10], sa.Addr[11] = 0xff, 0xff
		copy(sa.Addr[12:], net.ParseIP(name).To4())

		_ = syscall.Connect(fd, sa) // EINPROGRESS: the SYN is out (or dropped)

		time.Sleep(300 * time.Millisecond)
		os.Exit(bkHelperConnectFail)
	case "raw":
		// A raw UDP socket (CAP_NET_RAW) skips the sock_addr hooks.
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
		if err != nil {
			os.Exit(bkHelperResolveFail)
		}

		ip := net.ParseIP(name).To4()
		hdr := []byte{0x9c, 0x40, 0x00, 53, 0x00, 8, 0, 0} // sport 40000, dport 53, len 8
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], ip)

		if err = syscall.Sendto(fd, hdr, 0, sa); err != nil {
			os.Exit(bkHelperConnectFail)
		}

		os.Exit(bkHelperConnected)
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)

	var resp *dns.Msg

	if mode == "tcp" {
		c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}

		r, _, err := c.Exchange(q, bkDNSFakeResolver)
		if err != nil {
			os.Exit(bkHelperResolveFail)
		}

		resp = r
	} else {
		dst, _ := net.ResolveUDPAddr("udp4", bkDNSFakeResolver)

		pc, err := net.ListenUDP("udp4", nil)
		if err != nil {
			os.Exit(bkHelperResolveFail)
		}

		buf, _ := q.Pack()

		_ = pc.SetDeadline(time.Now().Add(2 * time.Second))

		if _, err = pc.WriteToUDP(buf, dst); err != nil {
			os.Exit(bkHelperResolveFail)
		}

		rb := make([]byte, 4096)

		n, from, err := pc.ReadFromUDP(rb)
		if err != nil {
			os.Exit(bkHelperResolveFail)
		}

		if !from.IP.Equal(dst.IP) || from.Port != dst.Port {
			os.Exit(bkHelperBadSource)
		}

		resp = new(dns.Msg)
		if err = resp.Unpack(rb[:n]); err != nil {
			os.Exit(bkHelperResolveFail)
		}
	}

	var ip string

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ip = a.A.String()

			break
		}
	}

	if ip == "" {
		os.Exit(bkHelperResolveFail)
	}

	fmt.Println("IP=" + ip) //nolint:forbidigo // helper output

	c, err := net.DialTimeout("tcp4", net.JoinHostPort(ip, port), 1200*time.Millisecond)
	if err != nil {
		os.Exit(bkHelperConnectFail)
	}

	_ = c.Close()

	os.Exit(bkHelperConnected)
}

// runResolveIn runs the helper inside cgroupDir and returns its exit code
// and the IP it resolved.
func runResolveIn(t *testing.T, cgroupDir, name, port, mode string) (int, string) {
	t.Helper()

	fd, err := syscall.Open(cgroupDir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open cgroup dir: %v", err)
	}

	defer func() { _ = syscall.Close(fd) }()

	var out bytes.Buffer

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperBKResolveConnect$")
	cmd.Env = append(os.Environ(), bkDNSHelperEnv+"="+name, "LEITWACHT_BK_DNS_PORT="+port, "LEITWACHT_BK_DNS_MODE="+mode)
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}

	code := 0

	if runErr := cmd.Run(); runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			t.Fatalf("run helper: %v", runErr)
		}

		code = ee.ExitCode()
	}

	ip := ""

	for _, l := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, "IP="); ok {
			ip = strings.TrimSpace(v)
		}
	}

	return code, ip
}

// TestIntegrationBuildKitNoCookieVariantLoads loads the object variant for
// kernels without bpf_get_netns_cookie in cgroup_skb and attaches it, so
// the whole BuildKit attach cannot depend on that helper.
func TestIntegrationBuildKitNoCookieVariantLoads(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	bkForceNoNetnsCookie = true

	t.Cleanup(func() { bkForceNoNetnsCookie = false })

	platform := &LinuxPlatform{Logger: quietLog()}

	dpIface, err := platform.LoadBuildKitEBPF(nil)
	if err != nil {
		t.Fatalf("no-cookie variant did not load on kernel %s: %v", kernelRelease(), err)
	}

	dp := dpIface.(*linuxBKHandle)

	t.Cleanup(func() { _ = dp.Close() })

	parent := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("lwtest-bknc-%d", os.Getpid()))
	if err = os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Remove(parent) })

	l, err := dp.AttachCgroup(parent)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	_ = l.Close()
}

// TestIntegrationBuildKitDNSProxy runs the whole build DNS path on real
// cgroups: the sock_addr redirect at a parent cgroup, the proxy bound
// through Platform.BindInNetns, per-query attribution through the dns_pid
// subtree tracking, the binder's slots and the egress filter.
//
//   - redirect off: the fake cluster DNS is unreachable (resolve fails);
//   - enforce cgroup, allowed name: the answer is real, its address was
//     seeded into the slot and the connect passes, with no drop rows;
//   - enforce cgroup, unlisted name: the sinkhole is returned and the
//     connect to it is dropped (sinkhole_hit);
//   - shadow cgroup, unlisted name: answered for real, connect passes,
//     would_block recorded;
//   - unbound cgroup: answered, connect passes (audit, pending_bind);
//   - both UDP (unconnected socket: the reply source is rewritten back)
//     and TCP DNS are redirected.
//
// Needs root, cgroup v2, the BPF LSM, fexit support and `ip`.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationBuildKitDNSProxy -v -count=1.
func TestIntegrationBuildKitDNSProxy(t *testing.T) { //nolint:gocyclo,funlen // one scenario, many assertions
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := quietLog()
	platform := &LinuxPlatform{Logger: logger}

	dpIface, err := platform.LoadBuildKitEBPF(nil)
	if err != nil {
		t.Fatalf("load egress_bk — it did not verify on kernel %s: %v", kernelRelease(), err)
	}

	dp := dpIface.(*linuxBKHandle)

	t.Cleanup(func() { _ = dp.Close() })

	if dp.lsm == nil {
		t.Skip("BPF LSM unavailable: no socket attribution, no events")
	}

	tracker, err := NewDNSPIDTracker(logger)
	if err != nil {
		t.Skipf("dns pid tracker unavailable on kernel %s: %v", kernelRelease(), err)
	}

	t.Cleanup(tracker.Close)

	const (
		allowedIP = "198.51.100.7" // what the fake upstream answers for every A query
		port      = 18443
	)

	if out, addErr := exec.Command("ip", "addr", "add", allowedIP+"/32", "dev", "lo").CombinedOutput(); addErr != nil {
		t.Skipf("cannot add test address: %v (%s)", addErr, out)
	}

	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", allowedIP+"/32", "dev", "lo").Run() })

	ln, err := net.Listen("tcp4", net.JoinHostPort(allowedIP, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			_ = c.Close()
		}
	}()

	upstream, _ := startUpstream(t)

	parent := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("lwtest-bkdns-%d", os.Getpid()))
	if err = os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent cgroup: %v", err)
	}

	children := map[string]string{}

	for _, n := range []string{"run-enf", "run-shadow", "run-unbound"} {
		p := filepath.Join(parent, n)
		if err = os.Mkdir(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}

		children[n] = p
	}

	t.Cleanup(func() {
		for _, p := range children {
			_ = os.Remove(p)
		}

		_ = os.Remove(parent)
	})

	parentID, err := platform.CgroupID(parent)
	if err != nil {
		t.Fatal(err)
	}

	ids := map[string]uint64{}

	for n, p := range children {
		if ids[n], err = platform.CgroupID(p); err != nil {
			t.Fatal(err)
		}
	}

	if err = dp.SetConfig(BKConfig{ParentIDs: []uint64{parentID}}); err != nil {
		t.Fatalf("set config: %v", err)
	}

	if err = tracker.AddRunParent(parentID); err != nil {
		t.Fatalf("register dns run parent: %v", err)
	}

	t.Cleanup(func() { tracker.RemoveRunParent(parentID) })

	if err = dp.AddSockKnownAncestor(parentID); err != nil {
		t.Fatalf("register subtree: %v", err)
	}

	t.Cleanup(func() { dp.RemoveSockKnownAncestor(parentID) })

	link, err := dp.AttachCgroup(parent)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Cleanup(func() { _ = link.Close() })

	if !dp.DNSRedirectAvailable() {
		t.Fatalf("sock_addr redirect programs did not attach on kernel %s", kernelRelease())
	}

	recorder := NewViolationRecorder(nil)

	stop, err := dp.StartRingbufReader(t.Context(), func(uint64) *ViolationRecorder { return recorder })
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(stop)

	// Policies: g/enf allows ok.example.org on the test port; g/shadow the
	// same in shadow mode.
	src := newFakeSource()
	rules := []BuildFQDNRule{{Pattern: "ok.example.org", Allow: true, Prio: policy.RulePriority(1), Ports: []int{port}}}

	enf := BuildPolicy{Mode: BuildModeEnforce, Version: 1, FQDNRules: rules}
	shd := BuildPolicy{Mode: BuildModeShadow, Version: 1, FQDNRules: rules}

	src.set("g/enf", "j", enf)
	src.set("g/shadow", "j", shd)

	binder := NewBuildPolicyBinder(src, dp, logger)
	t.Cleanup(binder.Close)

	binder.OnBind(ids["run-enf"], exactBinding("g/enf", "j"))
	binder.OnBind(ids["run-shadow"], exactBinding("g/shadow", "j"))

	d, err := newBuildDNS(BuildDNSConfig{
		Tracker:              tracker,
		Upstreams:            []string{upstream},
		ExpansionSuppression: ExpansionSuppressionOff,
		NetnsPID:             func() (int, error) { return os.Getpid(), nil },
		PollInterval:         50 * time.Millisecond,
		ProbeInterval:        200 * time.Millisecond, // exercises the real in-netns probe
	}, logger, dp, binder, recorder, []uint64{parentID}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	d.bind = platform.BindInNetns
	d.netnsInode = platform.NetnsInode
	d.newDialer = platform.NewUpstreamDialer
	d.sample = func() []runSample {
		ino, _ := platform.NetnsInode(os.Getpid())

		return []runSample{{pid: os.Getpid(), ino: ino}}
	}

	count := func(cg uint64, ip, action string) int {
		n := 0

		vs, _ := recorder.Snapshot()
		for _, v := range vs {
			if v.CgroupID == cg && v.IP == ip && v.Action == action {
				n++
			}
		}

		return n
	}

	waitUntil := func(what string, pred func() bool) {
		t.Helper()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if pred() {
				return
			}

			time.Sleep(25 * time.Millisecond)
		}

		vs, _ := recorder.Snapshot()
		t.Errorf("no event: %s; recorded %d rows: %+v", what, len(vs), vs)
	}

	portStr := strconv.Itoa(port)

	// 1. No proxy yet: the cluster DNS address is unreachable.
	if code, _ := runResolveIn(t, children["run-enf"], "ok.example.org", portStr, "udp"); code != bkHelperResolveFail {
		t.Fatalf("redirect not yet on: helper exit %d, want resolve failure %d", code, bkHelperResolveFail)
	}

	// 2. Bring the proxy up through the real lifecycle.
	d.start(t.Context())

	t.Cleanup(d.Close)

	if !d.Active() || !binder.DNSProxyActive() {
		t.Fatal("proxy not active after start")
	}

	// 3. Enforce cgroup, allowed name (unconnected UDP, then TCP).
	for _, mode := range []string{"udp", "tcp"} {
		code, ip := runResolveIn(t, children["run-enf"], "ok.example.org", portStr, mode)
		if code != bkHelperConnected || ip != allowedIP {
			t.Fatalf("enforce/allowed/%s: exit %d ip %q (4 = reply source not rewritten back, 2 = no answer)", mode, code, ip)
		}
	}

	if n := count(ids["run-enf"], allowedIP, "packet_dropped"); n != 0 {
		t.Errorf("allowed name produced %d drop rows", n)
	}

	waitUntil("enforce -> allowed packet_allowed", func() bool { return count(ids["run-enf"], allowedIP, "packet_allowed") >= 1 })

	// 4. Enforce cgroup, unlisted name: sinkhole, connect dropped.
	code, ip := runResolveIn(t, children["run-enf"], "evil.example.net", portStr, "udp")
	if ip != SinkholeIPv4 || code != bkHelperConnectFail {
		t.Fatalf("enforce/unlisted: exit %d ip %q, want the sinkhole and a failed connect", code, ip)
	}

	waitUntil("enforce -> sinkhole_hit", func() bool { return count(ids["run-enf"], SinkholeIPv4, "sinkhole_hit") >= 1 })

	// 5. Shadow cgroup: unlisted name answered for real, connect passes,
	// would_block recorded (nothing seeded it).
	code, ip = runResolveIn(t, children["run-shadow"], "evil.example.net", portStr, "udp")
	if code != bkHelperConnected || ip != allowedIP {
		t.Fatalf("shadow/unlisted: exit %d ip %q, want a real answer and a passing connect", code, ip)
	}

	waitUntil("shadow -> would_block", func() bool { return count(ids["run-shadow"], allowedIP, "would_block") >= 1 })

	// 6. Unbound cgroup: audit.
	code, ip = runResolveIn(t, children["run-unbound"], "evil.example.net", portStr, "udp")
	if code != bkHelperConnected || ip != allowedIP {
		t.Fatalf("unbound: exit %d ip %q, want answered + connected (audit)", code, ip)
	}

	waitUntil("unbound -> packet_observed", func() bool { return count(ids["run-unbound"], allowedIP, "packet_observed") >= 1 })

	// 7. Domain on the enforce cgroup's rows, none on the others'.
	vs, _ := recorder.Snapshot()
	d.StampDomains(vs)

	var stamped bool

	for _, v := range vs {
		if v.CgroupID == ids["run-enf"] && v.IP == allowedIP && v.Domain == "ok.example.org" && v.DomainSource == DomainSourceBuildDNSProxy {
			stamped = true
		}

		if v.CgroupID == ids["run-shadow"] && v.IP == allowedIP && v.Domain != "evil.example.net" && v.Domain != "" {
			t.Errorf("shadow row got a foreign domain: %+v", v)
		}
	}

	if !stamped {
		t.Errorf("enforce row not stamped with the resolved domain: %+v", vs)
	}

	// 7b. Bypasses while the proxy is active: port 53 to anything but the
	// proxy is dropped in enforce, even a v4-mapped connect (never reaches
	// connect4) and a raw socket (skips the hooks).
	runResolveIn(t, children["run-enf"], "10.254.78.99", "53", "v4mapped")
	runResolveIn(t, children["run-enf"], "10.254.78.98", "53", "raw")

	waitUntil("v4-mapped :53 -> dns_bypass_dropped", func() bool { return count(ids["run-enf"], "10.254.78.99", "dns_bypass_dropped") >= 1 })
	waitUntil("raw :53 -> dns_bypass_dropped", func() bool { return count(ids["run-enf"], "10.254.78.98", "dns_bypass_dropped") >= 1 })

	// Shadow records would_block instead of dropping.
	runResolveIn(t, children["run-shadow"], "10.254.78.97", "53", "v4mapped")
	waitUntil("shadow v4-mapped :53 -> would_block", func() bool { return count(ids["run-shadow"], "10.254.78.97", "would_block") >= 1 })

	// The in-netns liveness probe ran against the real proxy meanwhile and
	// must not have unbound it.
	time.Sleep(500 * time.Millisecond)

	if !d.Active() {
		t.Fatal("liveness probe tore down a healthy proxy")
	}

	// 8. Stopping the proxy turns the redirect off: DNS no longer reaches
	// the fake resolver (a real buildkitd would reach its real upstream).
	d.Close()

	// The pin goes with the redirect: no drops once it is off.
	runResolveIn(t, children["run-enf"], "10.254.78.96", "53", "v4mapped")
	time.Sleep(200 * time.Millisecond)

	if n := count(ids["run-enf"], "10.254.78.96", "dns_bypass_dropped"); n != 0 {
		t.Errorf("pin still dropping port 53 after the proxy was stopped (%d)", n)
	}

	if binder.DNSProxyActive() {
		t.Error("binder still thinks the proxy is active after Close")
	}

	if code, _ = runResolveIn(t, children["run-enf"], "ok.example.org", portStr, "udp"); code != bkHelperResolveFail {
		t.Errorf("after Close helper exit %d, want resolve failure (redirect off)", code)
	}
}
