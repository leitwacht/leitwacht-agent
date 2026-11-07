//go:build linux && integration

package enforcer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// bkHelperEnv makes the test binary act as the connecting workload: it
// dials the target and exits 0 on success, 1 on failure.
const bkHelperEnv = "LEITWACHT_BK_HELPER_TARGET"

func TestHelperBKConnect(t *testing.T) {
	target := os.Getenv(bkHelperEnv)
	if target == "" {
		t.Skip("helper only")
	}

	c, err := net.DialTimeout("tcp4", target, 1500*time.Millisecond)
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

	fd, err := syscall.Open(cgroupDir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open cgroup dir: %v", err)
	}

	defer func() { _ = syscall.Close(fd) }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperBKConnect$")
	cmd.Env = append(os.Environ(), bkHelperEnv+"="+target)
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
