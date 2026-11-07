//go:build linux && integration

package enforcer

import (
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
)

// bkHelperEnv makes the test binary act as the connecting workload: it
// dials the target and exits 0 on success, 1 on failure.
const (
	bkHelperEnv        = "LEITWACHT_BK_HELPER_TARGET"
	bkHelperTimeoutEnv = "LEITWACHT_BK_HELPER_TIMEOUT_MS"
)

func TestHelperBKConnect(t *testing.T) {
	target := os.Getenv(bkHelperEnv)
	if target == "" {
		t.Skip("helper only")
	}

	timeout := 1500 * time.Millisecond

	if ms, perr := strconv.Atoi(os.Getenv(bkHelperTimeoutEnv)); perr == nil && ms > 0 {
		timeout = time.Duration(ms) * time.Millisecond
	}

	network := "tcp4"
	if strings.Contains(target, "[") {
		network = "tcp6"
	}

	c, err := net.DialTimeout(network, target, timeout)
	if err != nil {
		os.Exit(1)
	}

	_ = c.Close()

	os.Exit(0)
}

// runInCgroup starts the helper directly inside cgroupDir (clone into
// cgroup, so even the first socket belongs to it) and reports whether
// its connect succeeded.
func runInCgroup(t *testing.T, cgroupDir, target string) bool {
	t.Helper()

	return runInCgroupTimeout(t, cgroupDir, target, 0)
}

// runInCgroupTimeout is runInCgroup with a dial timeout (0 = default).
func runInCgroupTimeout(t *testing.T, cgroupDir, target string, timeout time.Duration) bool {
	t.Helper()

	fd, err := syscall.Open(cgroupDir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open cgroup dir: %v", err)
	}

	defer func() { _ = syscall.Close(fd) }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperBKConnect$")
	cmd.Env = append(os.Environ(), bkHelperEnv+"="+target)
	if timeout > 0 {
		cmd.Env = append(cmd.Env, bkHelperTimeoutEnv+"="+strconv.Itoa(int(timeout.Milliseconds())))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}

	return cmd.Run() == nil
}

// TestIntegrationBuildKitSlotDatapath loads egress_bk, attaches it at a
// parent cgroup with RUN-like children and checks the per-cgroup
// verdicts end to end:
//
//   - child A, bound to an enforce slot allowing X: connect X passes
//     (packet_allowed, deduped), connect Y is dropped (packet_dropped);
//   - child B, unbound: Y passes and is observed as pending_bind;
//   - child C, bound to a shadow slot: Y passes and is would_block.
//
// Needs root, cgroup v2, the BPF LSM (socket attribution) and `ip`.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationBuildKitSlotDatapath -v -count=1.
func TestIntegrationBuildKitSlotDatapath(t *testing.T) {
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

	// Two local addresses on lo, outside 127/8, so the program judges them.
	const (
		ipX  = "10.254.77.1"
		ipY  = "10.254.77.2"
		port = 18443
	)

	for _, a := range []string{ipX, ipY} {
		if out, addErr := exec.Command("ip", "addr", "add", a+"/32", "dev", "lo").CombinedOutput(); addErr != nil {
			t.Skipf("cannot add test address %s: %v (%s)", a, addErr, out)
		}

		a := a

		t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", a+"/32", "dev", "lo").Run() })
	}

	for _, lp := range []struct{ a, p string }{
		{ipX, strconv.Itoa(port)}, {ipY, strconv.Itoa(port)}, {ipX, "53"}, {ipY, "53"},
	} {
		a := lp.a

		ln, listenErr := net.Listen("tcp4", net.JoinHostPort(a, lp.p))
		if listenErr != nil {
			t.Fatalf("listen %s:%s: %v", a, lp.p, listenErr)
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
	}

	parent := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("lwtest-bk-%d", os.Getpid()))
	if err = os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent cgroup: %v", err)
	}

	children := map[string]string{}

	for _, n := range []string{"run-a", "run-b", "run-c"} {
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

	// The RUN level is found in the kernel from the parent id; ipX is the
	// "DNS upstream" of the port-53 pin.
	cfg := BKConfig{ParentIDs: []uint64{parentID}, DNSUpstreams: []net.IP{net.ParseIP(ipX)}}
	if err = dp.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	if err = dp.AddSockKnownAncestor(parentID); err != nil {
		t.Fatalf("register subtree: %v", err)
	}

	t.Cleanup(func() { dp.RemoveSockKnownAncestor(parentID) })

	link, err := dp.AttachCgroup(parent)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Cleanup(func() { _ = link.Close() })

	recorder := NewViolationRecorder(nil)

	stop, err := dp.StartRingbufReader(t.Context(), func(uint64) *ViolationRecorder { return recorder })
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(stop)

	ids := map[string]uint64{}

	for n, p := range children {
		if ids[n], err = platform.CgroupID(p); err != nil {
			t.Fatal(err)
		}
	}

	// ipY:53 is allowed by a rule too: the DNS pin must still win.
	allowX := BKSlotRules{Allow: []BuildIPRule{
		{IP: ipX, Port: port, Allow: true, Prio: 1},
		{IP: ipY, Port: 53, Allow: true, Prio: 2},
	}}

	if err = dp.InstallSlot(0, allowX); err != nil {
		t.Fatalf("install enforce slot: %v", err)
	}

	if err = dp.InstallSlot(1, allowX); err != nil {
		t.Fatalf("install shadow slot: %v", err)
	}

	t.Cleanup(func() { _ = dp.RemoveSlot(0); _ = dp.RemoveSlot(1) })

	if err = dp.SetCgroupPolicy(ids["run-a"], BKCgroupPolicy{Slot: 0, State: bkStateBound, Mode: bkModeBlock, Gen: 1}); err != nil {
		t.Fatal(err)
	}

	if err = dp.SetCgroupPolicy(ids["run-c"], BKCgroupPolicy{Slot: 1, State: bkStateBound, Mode: bkModeShadow, Gen: 1}); err != nil {
		t.Fatal(err)
	}

	x := net.JoinHostPort(ipX, strconv.Itoa(port))
	y := net.JoinHostPort(ipY, strconv.Itoa(port))

	// A: X passes (twice: the second must not add an event), Y dropped.
	if !runInCgroup(t, children["run-a"], x) || !runInCgroup(t, children["run-a"], x) {
		t.Error("bound enforce cgroup: connect to the allowed address failed")
	}

	if runInCgroup(t, children["run-a"], y) {
		t.Error("bound enforce cgroup: connect to the non-allowed address succeeded")
	}

	// DNS pin (BLOCK): port 53 to the upstream passes, to any other
	// address is dropped as a bypass, whatever the rules say.
	x53 := net.JoinHostPort(ipX, "53")
	y53 := net.JoinHostPort(ipY, "53")

	if !runInCgroup(t, children["run-a"], x53) {
		t.Error("DNS pin: connect to the configured upstream failed")
	}

	if runInCgroup(t, children["run-a"], y53) {
		t.Error("DNS pin: port 53 to a non-upstream address succeeded in BLOCK")
	}

	// Shadow records the bypass but passes.
	if !runInCgroup(t, children["run-c"], y53) {
		t.Error("DNS pin: shadow must pass")
	}

	// B: unbound, audit.
	if !runInCgroup(t, children["run-b"], y) {
		t.Error("unbound cgroup: connect must pass (audit)")
	}

	// C: shadow slot, passes.
	if !runInCgroup(t, children["run-c"], y) {
		t.Error("shadow cgroup: connect must pass")
	}

	count := func(cg uint64, ip, action string) (n int, pending bool) {
		vs, _ := recorder.Snapshot()
		for _, v := range vs {
			if v.CgroupID == cg && v.IP == ip && v.Action == action {
				n++

				pending = pending || v.EnforcementState == EnfStatePendingBind
			}
		}

		return n, pending
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

	waitUntil("A -> Y packet_dropped", func() bool { n, _ := count(ids["run-a"], ipY, "packet_dropped"); return n >= 1 })
	waitUntil("A -> X packet_allowed", func() bool { n, _ := count(ids["run-a"], ipX, "packet_allowed"); return n >= 1 })
	waitUntil("B -> Y packet_observed (pending_bind)", func() bool {
		n, pending := count(ids["run-b"], ipY, "packet_observed")

		return n >= 1 && pending
	})
	waitUntil("C -> Y would_block", func() bool { n, _ := count(ids["run-c"], ipY, "would_block"); return n >= 1 })

	waitUntil("A -> Y:53 dns_bypass_dropped", func() bool { n, _ := count(ids["run-a"], ipY, "dns_bypass_dropped"); return n >= 1 })
	waitUntil("C -> Y:53 would_block", func() bool {
		vs, _ := recorder.Snapshot()
		for _, v := range vs {
			if v.CgroupID == ids["run-c"] && v.IP == ipY && v.Port == 53 && v.Action == "would_block" {
				return true
			}
		}

		return false
	})

	allowedX := 0

	{
		vs, _ := recorder.Snapshot()
		for _, v := range vs {
			if v.CgroupID == ids["run-a"] && v.IP == ipX && v.Port == port && v.Action == "packet_allowed" {
				allowedX++
			}
		}
	}

	if n := allowedX; n != 1 {
		t.Errorf("packet_allowed events for A->X = %d, want exactly 1 (60s dedup)", n)
	}

	if n, _ := count(ids["run-a"], ipX, "packet_dropped"); n != 0 {
		t.Errorf("allowed address produced %d drop events", n)
	}

	// Layout mismatch: with a parent id that is nobody's ancestor the
	// level scan finds nothing, the cgroup is audit and says why.
	time.Sleep(1200 * time.Millisecond) // past the 1s event dedup window

	bogus := cfg
	bogus.ParentIDs = []uint64{parentID + 1_000_000}

	if err = dp.SetConfig(bogus); err != nil {
		t.Fatal(err)
	}

	if !runInCgroup(t, children["run-a"], y) {
		t.Error("level mismatch must run in audit (pass), never fail closed")
	}

	waitUntil("degraded_level row", func() bool {
		vs, _ := recorder.Snapshot()
		for _, v := range vs {
			if v.CgroupID == ids["run-a"] && v.IP == ipY && v.Action == "packet_observed" &&
				v.EnforcementState == EnfStateDegradedLevel && v.DegradedReason == DegradedRunLevel {
				return true
			}
		}

		return false
	})

	if err = dp.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// Entries are deletable; an unbound cgroup afterwards is audit again.
	if err = dp.DeleteCgroupPolicy(ids["run-a"]); err != nil {
		t.Fatal(err)
	}

	if !runInCgroup(t, children["run-a"], y) {
		t.Error("after DeleteCgroupPolicy the cgroup must fall back to audit (pass)")
	}
}

// TestIntegrationBuildKitSynHold checks the pre-bind SYN hold: a PENDING
// RUN cgroup's first SYN is dropped (syn_held), the kernel retransmit
// is judged by the slot once the cgroup is bound, and the hold never
// outlives its window or applies while disabled.
//
// Needs root, cgroup v2, the BPF LSM and `ip`.
func TestIntegrationBuildKitSynHold(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	platform := &LinuxPlatform{Logger: quietLog()}

	dpIface, err := platform.LoadBuildKitEBPF([]net.IPNet{{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)}})
	if err != nil {
		t.Fatalf("load egress_bk: %v", err)
	}

	dp := dpIface.(*linuxBKHandle)

	t.Cleanup(func() { _ = dp.Close() })

	if dp.lsm == nil {
		t.Skip("BPF LSM unavailable")
	}

	const (
		ipX  = "10.254.78.1"
		ipY  = "10.254.78.2"
		ipZ  = "10.254.78.3" // DNS upstream
		port = 18444
	)

	for _, a := range []string{ipX, ipY, ipZ} {
		if out, addErr := exec.Command("ip", "addr", "add", a+"/32", "dev", "lo").CombinedOutput(); addErr != nil {
			t.Skipf("cannot add test address %s: %v (%s)", a, addErr, out)
		}

		a := a

		t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", a+"/32", "dev", "lo").Run() })

		ln, listenErr := net.Listen("tcp4", net.JoinHostPort(a, strconv.Itoa(port)))
		if listenErr != nil {
			t.Fatalf("listen: %v", listenErr)
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
	}

	parent := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("lwtest-bkhold-%d", os.Getpid()))
	if err = os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}

	names := []string{"deny", "allow", "off", "expiry", "meta", "v6", "dot", "dns"}
	dirs := map[string]string{}
	ids := map[string]uint64{}

	t.Cleanup(func() {
		for _, p := range dirs {
			_ = os.Remove(p)
		}

		_ = os.Remove(parent)
	})

	for _, n := range names {
		dirs[n] = filepath.Join(parent, n)
		if err = os.Mkdir(dirs[n], 0o755); err != nil {
			t.Fatal(err)
		}

		if ids[n], err = platform.CgroupID(dirs[n]); err != nil {
			t.Fatal(err)
		}
	}

	parentID, err := platform.CgroupID(parent)
	if err != nil {
		t.Fatal(err)
	}

	cfg := BKConfig{ParentIDs: []uint64{parentID}, DNSUpstreams: []net.IP{net.ParseIP(ipZ)}, HoldWindow: 2 * time.Second}
	if err = dp.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}

	if err = dp.AddSockKnownAncestor(parentID); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { dp.RemoveSockKnownAncestor(parentID) })

	link, err := dp.AttachCgroup(parent)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = link.Close() })

	recorder := NewViolationRecorder(nil)

	stop, err := dp.StartRingbufReader(t.Context(), func(uint64) *ViolationRecorder { return recorder })
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(stop)

	// Slot 0 allows only X, enforce.
	if err = dp.InstallSlot(0, BKSlotRules{Allow: []BuildIPRule{{IP: ipX, Port: port, Allow: true, Prio: 1}}}); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = dp.RemoveSlot(0) })

	x := net.JoinHostPort(ipX, strconv.Itoa(port))
	y := net.JoinHostPort(ipY, strconv.Itoa(port))

	// IPv6 is optional: it needs a local address and a listener.
	const ip6 = "fd00:254::1"

	v6ok := false

	if out, addErr := exec.Command("ip", "-6", "addr", "add", ip6+"/128", "dev", "lo", "nodad").CombinedOutput(); addErr == nil {
		t.Cleanup(func() { _ = exec.Command("ip", "-6", "addr", "del", ip6+"/128", "dev", "lo").Run() })

		if ln, lerr := net.Listen("tcp6", net.JoinHostPort(ip6, strconv.Itoa(port))); lerr == nil {
			v6ok = true

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
		}
	} else {
		t.Logf("IPv6 hold case skipped: %v (%s)", addErr, out)
	}

	hasEvent := func(cg uint64, ip, action string) bool {
		vs, _ := recorder.Snapshot()
		for _, v := range vs {
			if v.CgroupID == cg && v.IP == ip && v.Action == action {
				return true
			}
		}

		return false
	}

	// connectBindingAfter dials target from the pending cgroup and binds
	// it to the enforce slot 300 ms in (a stand-in for the join).
	connectBindingAfter := func(name, target string) (bool, time.Duration) {
		go func() {
			time.Sleep(300 * time.Millisecond)

			if setErr := dp.SetCgroupPolicy(ids[name], BKCgroupPolicy{Slot: 0, State: bkStateBound, Mode: bkModeBlock, Gen: 1}); setErr != nil {
				t.Errorf("bind %s: %v", name, setErr)
			}
		}()

		start := time.Now()
		ok := runInCgroupTimeout(t, dirs[name], target, 5*time.Second)

		return ok, time.Since(start)
	}

	if err = dp.SetHold(true); err != nil {
		t.Fatal(err)
	}

	// Hold on, slot denies Y: the first SYN is held, the retransmit after
	// the bind is dropped by policy.
	if ok, _ := connectBindingAfter("deny", y); ok {
		t.Error("held SYN to a denied address got through after binding")
	}

	if !hasEvent(ids["deny"], ipY, ActionSynHeld) {
		t.Error("no syn_held event for the pending cgroup")
	}

	// Hold covers the hard-blocked metadata address: held while pending,
	// then dropped as a hard block by the enforce slot after binding.
	const meta = "169.254.169.254"

	if out, addErr := exec.Command("ip", "addr", "add", meta+"/32", "dev", "lo").CombinedOutput(); addErr != nil {
		t.Logf("metadata hold case skipped: %v (%s)", addErr, out)
	} else {
		t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", meta+"/32", "dev", "lo").Run() })

		if ok, _ := connectBindingAfter("meta", net.JoinHostPort(meta, "80")); ok {
			t.Error("metadata SYN got through the pre-bind window or the hard block")
		}

		if !hasEvent(ids["meta"], meta, ActionSynHeld) {
			t.Error("pending SYN to the metadata address was not held")
		}

		if !hasEvent(ids["meta"], meta, "packet_dropped") {
			t.Error("metadata retransmit after binding was not dropped as a hard block")
		}
	}

	// Trusted nets and DNS upstreams exempt ordinary destinations from the
	// hold, but never DoT (port 853) on a DNS upstream.
	if ok, took := connectBindingAfter("dot", net.JoinHostPort(ipZ, "853")); ok || took < 800*time.Millisecond {
		t.Errorf("DoT to a DNS upstream escaped the hold (ok=%v took=%v)", ok, took)
	}

	if !hasEvent(ids["dot"], ipZ, ActionSynHeld) {
		t.Error("pending SYN to a DNS upstream on 853 was not held")
	}

	start0 := time.Now()
	if !runInCgroupTimeout(t, dirs["dns"], net.JoinHostPort(ipZ, strconv.Itoa(port)), 5*time.Second) || time.Since(start0) > 700*time.Millisecond {
		t.Error("a DNS-upstream destination must stay exempt from the hold")
	}

	if hasEvent(ids["dns"], ipZ, ActionSynHeld) {
		t.Error("syn_held for an exempt DNS upstream")
	}

	// IPv6 SYNs from a pending cgroup are held too (and dropped once
	// bound to an enforce slot, which has no IPv6 support).
	if v6ok {
		if ok, _ := connectBindingAfter("v6", net.JoinHostPort(ip6, strconv.Itoa(port))); ok {
			t.Error("IPv6 SYN got through the pre-bind window")
		}

		if !hasEvent(ids["v6"], "::", ActionSynHeld) {
			t.Error("pending IPv6 SYN was not held")
		}
	}

	// Hold on, slot allows X: the connect succeeds after the retransmit.
	ok, took := connectBindingAfter("allow", x)
	if !ok {
		t.Error("held SYN to an allowed address never connected after binding")
	}

	if took < 800*time.Millisecond {
		t.Errorf("connect took %v; the SYN was not held until the retransmit", took)
	}

	if !hasEvent(ids["allow"], ipX, ActionSynHeld) {
		t.Error("no syn_held event for the allowed destination")
	}

	// Hold disabled: a pending cgroup passes at once.
	if err = dp.SetHold(false); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if !runInCgroupTimeout(t, dirs["off"], y, 5*time.Second) || time.Since(start) > 700*time.Millisecond {
		t.Errorf("hold disabled: pending connect must pass immediately (took %v)", time.Since(start))
	}

	if hasEvent(ids["off"], ipY, ActionSynHeld) {
		t.Error("syn_held recorded while the hold was disabled")
	}

	// Window expiry: with a 300 ms window the 1 s retransmit passes in
	// audit (never fail-closed).
	cfg.HoldWindow = 300 * time.Millisecond
	if err = dp.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}

	if err = dp.SetHold(true); err != nil {
		t.Fatal(err)
	}

	start = time.Now()
	if !runInCgroupTimeout(t, dirs["expiry"], y, 5*time.Second) {
		t.Error("after the hold window the pending cgroup must pass (audit)")
	}

	if took = time.Since(start); took < 800*time.Millisecond {
		t.Errorf("expiry case took %v; the first SYN was not held", took)
	}
}
