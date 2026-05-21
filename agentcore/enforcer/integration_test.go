//go:build linux && integration

package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// TestIntegrationDNSRecording launches a real container via ctr, attaches the
// full enforcement stack, runs curl inside it, and verifies DNS activity is
// recorded. Requires root + containerd running.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationDNSRecording -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationDNSRecording(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	// Check containerd is available.
	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-test"
		testTask      = "leitwacht-integ-test"
	)

	// Pull image if not present.
	_ = exec.Command("ctr", "image", "pull", testImage).Run()

	// Clean up any leftover from a previous failed run.
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	// Create container with wget as entrypoint (with delay so enforcement attaches first).
	// Using entrypoint (not ctr task exec) puts the process in the container's cgroup,
	// which is what K8s does for job containers.
	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", "sleep 3 && wget -q -O /dev/null --timeout=5 http://example.com/ || true; sleep 120").CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	// Get the container's init PID.
	pidOut, err := exec.Command("ctr", "task", "ls").CombinedOutput()
	if err != nil {
		t.Fatalf("ctr task ls: %v\n%s", err, pidOut)
	}

	var pid int

	for _, line := range strings.Split(string(pidOut), "\n") {
		if strings.Contains(line, testTask) {
			_, scanErr := fmt.Sscanf(line, "%s %d", new(string), &pid)
			if scanErr != nil {
				t.Fatalf("parse pid from %q: %v", line, scanErr)
			}

			break
		}
	}

	if pid == 0 {
		t.Fatalf("could not find PID for task %s in:\n%s", testTask, pidOut)
	}

	t.Logf("container PID: %d", pid)

	// Set up loopback in the container netns.
	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid), "ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	// Create the enforcement manager with real platform.
	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	err = mgr.StartDNSPIDTracker()
	if err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}
	err = mgr.StartCredwatch()
	if err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	// Build a policy that allows example.com in audit mode.
	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/integration",
		Action:      "audit",
		RuleSets: map[string][]policy.Rule{
			"": {
				{Pattern: "example.com", PatternType: policy.PatternFQDN, Action: policy.ActionAllow, Ports: []int{443, 80}},
			},
		},
	}
	pol.BuildLookups()

	// Attach enforcement to the container.
	info := ContainerInfo{
		ContainerID: testContainer + "000", // pad to 12 chars for log prefix
		ProjectPath: "test/integration",
	}

	e, err := mgr.Attach(context.Background(), info, pid, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	if e == nil {
		t.Fatal("expected non-nil enforcer")
	}

	t.Logf("enforcement attached, cgroupID=%d, cgroup=%s", e.cgroupID, e.cgroup)

	// Verify the recorder is registered (regression check).
	nctx := e.ctx
	if nctx.lookupDNSRecorder(e.cgroupID) == nil {
		t.Fatal("lookupDNSRecorder returned nil — recorder not registered before proxy started")
	}

	// The entrypoint (sh -c "sleep 3 && wget ...") will make the DNS query
	// from the container's own cgroup (not the shim's cgroup like ctr task exec).
	// This matches K8s behavior where the job script is the entrypoint.
	t.Log("waiting for entrypoint wget to make DNS query...")
	time.Sleep(6 * time.Second)

	// Detach and verify results.
	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	t.Logf("detach result: violations=%d dns_entries=%d bytes_sent=%d",
		len(result.Stats.Violations), len(result.Stats.DNSActivity), result.Stats.TotalBytesSent)

	for _, dns := range result.Stats.DNSActivity {
		t.Logf("  dns: domain=%s ips=%v pid=%d comm=%s parent_comm=%s binary_path=%s",
			dns.Domain, dns.ResolvedIPs, dns.PID, dns.Comm, dns.ParentComm, dns.BinaryPath)
	}

	for _, v := range result.Stats.Violations {
		t.Logf("  violation: domain=%s ip=%s action=%s pid=%d comm=%s parent_comm=%s binary_path=%s",
			v.Domain, v.IP, v.Action, v.PID, v.Comm, v.ParentComm, v.BinaryPath)
	}

	if len(result.Stats.DNSActivity) == 0 {
		t.Fatal("expected dns_entries > 0 — DNS recording is broken")
	}

	// Verify we got the right domain and parent process attribution.
	found := false

	for _, dns := range result.Stats.DNSActivity {
		if dns.Domain == "example.com" {
			found = true

			// The entrypoint is sh -c "... wget ...", so wget's parent is sh.
			if dns.Comm == "" {
				t.Error("expected comm to be populated for example.com DNS entry")
			}
			if dns.ParentComm == "" {
				t.Error("expected parent_comm to be populated for example.com DNS entry")
			}
			if dns.ParentComm == dns.Comm {
				t.Logf("parent_comm == comm (%s) — process may have been exec'd directly", dns.Comm)
			} else {
				t.Logf("parent process attribution: %s -> %s -> example.com", dns.ParentComm, dns.Comm)
			}

			if dns.BinaryPath == "" {
				t.Log("binary_path empty — may indicate LSM + tracepoint both missed, or exec happened before agent tracepoints attached")
			} else {
				t.Logf("binary_path: %s", dns.BinaryPath)
			}

			break
		}
	}

	if !found {
		t.Error("expected example.com in DNS activity")
	}
}

// TestIntegrationMultiContainer simulates a K8S pod with two sibling containers
// sharing a network namespace. Both make DNS queries; both should get recorded.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationMultiContainer -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationMultiContainer(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage  = "docker.io/library/alpine:latest"
		container1 = "leitwacht-integ-c1"
		container2 = "leitwacht-integ-c2"
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()

	// Clean up leftovers.
	for _, c := range []string{container1, container2} {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", c).Run()
		_ = exec.Command("ctr", "task", "delete", c).Run()
		_ = exec.Command("ctr", "container", "delete", c).Run()
	}

	// Start first container (creates its own netns).
	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, container1, "sleep", "120").CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run c1: %v\n%s", err, out)
	}

	// Get PID of first container.
	pid1 := getTaskPID(t, container1)
	t.Logf("container1 PID: %d", pid1)

	// Start second container sharing the first container's netns (simulates K8S pod).
	// We use unshare to create a process, then move it into c1's netns.
	cmd2 := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid1), "sleep", "120")
	cmd2.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd2.Start()
	if err != nil {
		t.Fatalf("start sibling: %v", err)
	}

	pid2 := cmd2.Process.Pid
	t.Logf("container2 (sibling) PID: %d", pid2)

	// Create a separate cgroup for the sibling (like K8S gives each container its own).
	siblingCgroup := "/sys/fs/cgroup/leitwacht-integ-sibling"
	err = os.MkdirAll(siblingCgroup, 0o755)
	if err != nil {
		t.Fatalf("create sibling cgroup: %v", err)
	}

	err = os.WriteFile(filepath.Join(siblingCgroup, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid2)), 0o644)
	if err != nil {
		t.Fatalf("move sibling to cgroup: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd2.Process.Kill()
		_ = cmd2.Wait()
		_ = os.Remove(siblingCgroup)

		for _, c := range []string{container1, container2} {
			_ = exec.Command("ctr", "task", "kill", "-s", "9", c).Run()
			time.Sleep(100 * time.Millisecond)
			_ = exec.Command("ctr", "task", "delete", c).Run()
			_ = exec.Command("ctr", "container", "delete", c).Run()
		}
	})

	// Bring up loopback in the shared netns.
	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid1), "ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("loopback: %v\n%s", loErr, loOut)
	}

	// Set up enforcement manager.
	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	err = mgr.StartDNSPIDTracker()
	if err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}
	err = mgr.StartCredwatch()
	if err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/multi",
		Action:      "audit",
		RuleSets: map[string][]policy.Rule{
			"": {
				{Pattern: "example.com", PatternType: policy.PatternFQDN, Action: policy.ActionAllow, Ports: []int{443, 80}},
				{Pattern: "httpbin.org", PatternType: policy.PatternFQDN, Action: policy.ActionAllow, Ports: []int{443, 80}},
			},
		},
	}
	pol.BuildLookups()

	// Attach first container (creator).
	e1, err := mgr.Attach(context.Background(), ContainerInfo{
		ContainerID: container1 + "000",
		ProjectPath: "test/multi",
	}, pid1, pol)
	if err != nil {
		t.Fatalf("attach c1: %v", err)
	}

	if e1 == nil {
		t.Fatal("c1 should attach")
	}

	t.Logf("c1 attached: cgroupID=%d", e1.cgroupID)

	// Attach second container (joiner — same netns, different cgroup).
	e2, err := mgr.Attach(context.Background(), ContainerInfo{
		ContainerID: container2 + "000",
		ProjectPath: "test/multi",
		CgroupPath:  siblingCgroup,
	}, pid2, pol)
	if err != nil {
		t.Fatalf("attach c2: %v", err)
	}

	if e2 == nil {
		t.Fatal("c2 should attach (sibling joins shared context)")
	}

	t.Logf("c2 attached: cgroupID=%d", e2.cgroupID)

	// Verify they share the same NetnsContext.
	if e1.ctx != e2.ctx {
		t.Error("siblings should share NetnsContext")
	}

	if mgr.Count() != 2 {
		t.Errorf("count = %d, want 2", mgr.Count())
	}

	// Container 1 queries example.com via ctr exec (runs inside the container).
	wget1 := exec.Command("ctr", "task", "exec", "--exec-id", "dns1", container1,
		"wget", "-q", "-O", "/dev/null", "--timeout=5", "http://example.com/")
	_ = wget1.Run() // may fail on connect, that's fine

	// Container 2 queries httpbin.org. Since the sibling is a bare process
	// (not a ctr container), we exec inside container1's task context which
	// shares the same netns. Both queries go through the shared DNS proxy.
	wget2 := exec.Command("ctr", "task", "exec", "--exec-id", "dns2", container1,
		"wget", "-q", "-O", "/dev/null", "--timeout=5", "http://httpbin.org/get")
	_ = wget2.Run()

	time.Sleep(500 * time.Millisecond)

	// Detach both and check results.
	r1 := mgr.Detach(container1 + "000")
	r2 := mgr.Detach(container2 + "000")

	if r1 == nil || r2 == nil {
		t.Fatal("expected non-nil detach results")
	}

	t.Logf("c1: violations=%d dns_entries=%d bytes=%d", len(r1.Stats.Violations), len(r1.Stats.DNSActivity), r1.Stats.TotalBytesSent)
	t.Logf("c2: violations=%d dns_entries=%d bytes=%d", len(r2.Stats.Violations), len(r2.Stats.DNSActivity), r2.Stats.TotalBytesSent)

	for _, d := range r1.Stats.DNSActivity {
		t.Logf("  c1 dns: %s -> %v", d.Domain, d.ResolvedIPs)
	}

	for _, d := range r2.Stats.DNSActivity {
		t.Logf("  c2 dns: %s -> %v", d.Domain, d.ResolvedIPs)
	}

	// Both DNS queries go through c1's ctr exec (shared netns), so both
	// land on c1's recorder (fallback — kprobe cgroup mismatch). The key
	// assertions: both containers attached, shared context works, and the
	// shared DNS proxy captured both domains.
	allDNS := make([]DNSActivityEntry, 0, len(r1.Stats.DNSActivity)+len(r2.Stats.DNSActivity))
	allDNS = append(allDNS, r1.Stats.DNSActivity...)
	allDNS = append(allDNS, r2.Stats.DNSActivity...)
	if len(allDNS) == 0 {
		t.Fatal("expected dns_entries > 0 across both containers")
	}

	domains := map[string]bool{}
	for _, d := range allDNS {
		domains[d.Domain] = true
	}

	if !domains["example.com"] {
		t.Error("expected example.com in combined DNS activity")
	}

	if !domains["httpbin.org"] {
		t.Error("expected httpbin.org in combined DNS activity")
	}

	t.Logf("multi-container test passed: %d domains recorded, shared context verified", len(domains))
}

// TestIntegrationBinaryPathMovedBinary exercises the forensic use case
// binary_path was built for: an attacker copies a legitimate binary to a
// suspicious location and runs it from there. bpf_d_path should report
// the *actual* loaded binary path (/tmp/.cache/wget), not the canonical
// install path (/bin/busybox), and not argv[0].
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationBinaryPathMovedBinary -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationBinaryPathMovedBinary(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-mv"
		testTask      = "leitwacht-integ-mv"
		// Inside the container: copy busybox to a suspicious-looking
		// location, name it wget, run it. This mimics a supply-chain
		// compromise where a dropped binary impersonates a tool.
		attackerScript = "sleep 3 && " +
			"mkdir -p /tmp/.cache && " +
			"cp /bin/busybox /tmp/.cache/wget && " +
			"/tmp/.cache/wget -q -O /dev/null --timeout=5 http://example.com/ || true; " +
			"sleep 120"
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", attackerScript).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/moved-binary",
		Action:      "audit",
		RuleSets: map[string][]policy.Rule{
			"": {
				{Pattern: "example.com", PatternType: policy.PatternFQDN, Action: policy.ActionAllow, Ports: []int{443, 80}},
			},
		},
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/moved-binary",
	}

	_, err = mgr.Attach(context.Background(), info, pid, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Log("waiting for /tmp/.cache/wget DNS query...")
	time.Sleep(6 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	t.Logf("detach: dns_entries=%d", len(result.Stats.DNSActivity))

	var exampleEntry *DNSActivityEntry

	for i := range result.Stats.DNSActivity {
		d := &result.Stats.DNSActivity[i]
		t.Logf("  dns: domain=%s pid=%d comm=%s binary_path=%s",
			d.Domain, d.PID, d.Comm, d.BinaryPath)

		if d.Domain == "example.com" {
			exampleEntry = d
		}
	}

	if exampleEntry == nil {
		t.Fatal("expected example.com in DNS activity")
	}

	// The critical assertion: binary_path reflects the actual ELF that was
	// loaded, not argv[0] or the canonical install path. If the attacker's
	// script ran successfully, binary_path should be "/tmp/.cache/wget".
	// With LSM + bpf_d_path, this is container-relative, not the host
	// overlay path.
	if !strings.Contains(exampleEntry.BinaryPath, "/tmp/.cache/wget") {
		t.Errorf("expected binary_path to contain '/tmp/.cache/wget' (attacker drop location), got %q",
			exampleEntry.BinaryPath)
		t.Log("this probably means the LSM program didn't attach " +
			"(check for 'LSM program failed to verify' warnings), so " +
			"binary_path is coming from the tracepoint fallback which " +
			"reads bprm->filename directly — still useful but won't " +
			"show canonical resolution")
	} else {
		t.Logf("SUCCESS: binary_path=%s reveals the attacker-dropped location",
			exampleEntry.BinaryPath)
	}
}

// TestIntegrationBinaryPathShortLivedExecs reproduces the short-lived-process
// branch of the "empty binary_path" gap. The agent populates process_info
// via two lanes: (1) bpf_d_path in the LSM bprm_committed_creds program, and
// (2) sched_process_exec tracepoint fallback. Both fire at execve; both fill
// process_info keyed on pid. DNS attribution fires later on udp_sendmsg,
// then userspace looks up process_info[pid] for binary_path.
//
// For a process that execve's, fires DNS immediately, and exits within
// milliseconds, the exec event → map write → userspace-readable window can
// close before the DNS proxy does its lookup. On busy jobs (CI runners
// doing many nslookup/apk/git invocations), this shows up as a sizable
// fraction of DNS rows with pid + comm populated but binary_path empty.
//
// QA snapshot at 2026-04-21 showed ~33% of DNS rows empty over a 2h window,
// dominated by libuv-worker (threads, separate bug) and short-lived execs
// (nslookup, dig, apk) — this test hits the second class.
//
// Runs a 20-iteration nslookup loop from the container entrypoint, each
// to a unique subdomain to defeat resolver caching. Asserts that at least
// 80% of resulting DNS activity entries have non-empty binary_path. With
// the current code the assertion is expected to fail on the "empty" side
// — a green result means the fallback chain (process_info[tid] →
// process_info[tgid] → /proc/<pid>/exe) landed.
//
//	Run: sudo -E go test ./agentcore/enforcer/ -tags integration \
//	     -run TestIntegrationBinaryPathShortLivedExecs -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationBinaryPathShortLivedExecs(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-shortlived"
		testTask      = "leitwacht-integ-shortlived"
		// Each wget execves afresh, resolves a unique subdomain (no cache
		// hits), and exits. Using wget rather than nslookup because the
		// ctr-run netns doesn't have resolv.conf configured — nslookup
		// bails out before firing a query, but wget's getaddrinfo goes
		// through the proxy's DNS redirect regardless. 20 iterations at
		// ~200ms each gives the race plenty of firings. Trailing sleep
		// keeps the container alive past the detach so cleanup is
		// deterministic.
		script = "sleep 3 && " +
			"for i in $(seq 1 20); do " +
			"  wget -q -O /dev/null --timeout=2 --tries=1 http://host-$i.example.com/ 2>/dev/null || true; " +
			"done; " +
			"sleep 120"
		iterations = 20
		// Threshold intentionally conservative: the fix should push this
		// to 100%, but machine-to-machine variance on scheduler latency
		// means we tolerate up to 20% misses without flaking.
		minPopulatedRatio = 0.8
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	// Audit mode so every query is recorded regardless of allow-list.
	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/short-lived",
		Action:      "audit",
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/short-lived",
	}

	_, err = mgr.Attach(context.Background(), info, pid, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Wait for all 20 nslookups + some slack. Each takes ~200ms with
	// 1.1.1.1 as the resolver; allow 2× for loaded CI machines.
	t.Log("waiting for 20 short-lived nslookup execs...")
	time.Sleep(12 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	t.Logf("detach: dns_entries=%d", len(result.Stats.DNSActivity))

	var (
		total     int
		populated int
	)

	for i := range result.Stats.DNSActivity {
		d := &result.Stats.DNSActivity[i]

		// Only count entries from our test loop; ignore any cluster.local
		// /.svc noise leaked in via resolver search domains.
		if !strings.HasPrefix(d.Domain, "host-") {
			continue
		}

		total++

		t.Logf("  dns: domain=%s pid=%d comm=%s binary_path=%q",
			d.Domain, d.PID, d.Comm, d.BinaryPath)

		if d.BinaryPath != "" {
			populated++
		}
	}

	if total < iterations/2 {
		t.Fatalf("expected ≥%d host-*.example.com DNS entries, got %d — "+
			"nslookup loop may not have run (check container entrypoint logs)",
			iterations/2, total)
	}

	ratio := float64(populated) / float64(total)
	t.Logf("binary_path populated ratio: %d/%d = %.2f (threshold %.2f)",
		populated, total, ratio, minPopulatedRatio)

	if ratio < minPopulatedRatio {
		t.Errorf("only %d/%d (%.0f%%) DNS entries have binary_path populated; "+
			"expected ≥%.0f%%. This is the short-lived-exec race: process_info "+
			"gets populated by sched_process_exec/LSM, but the DNS-proxy lookup "+
			"via process_info[pid] happens before the entry has been written "+
			"(or the process has already exited). Fix: fall back to "+
			"process_info[tgid] and /proc/<pid>/exe in LookupWithBinary.",
			populated, total, ratio*100, minPopulatedRatio*100)
	}
}

// TestIntegrationAttributionBurst fires a large burst of DNS queries from
// a single container and asserts that attribution (pid/comm) is preserved
// for nearly all of them. The pre-v1 BPF LRU hash (4096 entries) evicted
// under burst load; the replacement design (65536-entry LRU hash, looked
// up synchronously from userspace) should hold up at 100%.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationAttributionBurst -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationAttributionBurst(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-burst"
		testTask      = "leitwacht-integ-burst"
		burstCount    = 500
		// Short shell loop: burstCount unique DNS queries via nslookup.
		// nslookup uses the container's default resolver; nftables DNAT
		// rewrites dst:53 → our proxy:15353. NXDOMAIN results are fine —
		// we only care that the kprobe fired and attribution was captured.
		burstScript = "sleep 3 && " +
			"for i in $(seq 1 500); do " +
			"  nslookup test-$i.burst.example 2>/dev/null >/dev/null; " +
			"done; " +
			"sleep 120"
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", burstScript).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	upstreamAddr, stopUpstream := startFakeNXDomainUpstream(t)
	t.Cleanup(stopUpstream)

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{upstreamAddr}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/burst",
		Action:      "audit", // audit so all queries forward and record
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/burst",
	}

	_, err = mgr.Attach(context.Background(), info, pid, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Wait for the burst to complete. 500 nslookups through local proxy
	// + upstream typically ~15-30s.
	t.Log("waiting for burst to finish (up to 45s)...")
	time.Sleep(45 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	total := 0
	attributed := 0
	var unattributedSamples []string

	for _, d := range result.Stats.DNSActivity {
		if !strings.Contains(d.Domain, "burst.example") {
			// Skip startup noise — only count our burst domains.
			continue
		}

		total++

		if d.PID != 0 && d.Comm != "" {
			attributed++
		} else if len(unattributedSamples) < 5 {
			unattributedSamples = append(unattributedSamples,
				fmt.Sprintf("%s(pid=%d comm=%q)", d.Domain, d.PID, d.Comm))
		}
	}

	t.Logf("burst result: %d/%d queries attributed (%.1f%%), %d total dns entries including noise",
		attributed, total, float64(attributed)*100/float64(total), len(result.Stats.DNSActivity))

	if len(unattributedSamples) > 0 {
		t.Logf("sample unattributed: %v", unattributedSamples)
	}

	if total < burstCount/2 {
		t.Errorf("only %d of expected ~%d burst queries recorded — burst script may have failed", total, burstCount)
	}

	// Accept ≥99% attribution as healthy (the old LRU would have been
	// well below 50% under the same burst at 4096 host-global entries
	// during CI concurrency).
	minRatio := 0.99
	actualRatio := float64(attributed) / float64(total)
	if actualRatio < minRatio {
		t.Errorf("attribution ratio %.2f%% below threshold %.0f%% — BPF attribution hash write or proxy lookup may be racing",
			actualRatio*100, minRatio*100)
	}
}

// TestIntegrationTCPDNSAttribution verifies that DNS-over-TCP queries are
// attributed. The existing UDP path is exercised by TestIntegrationDNSRecording;
// this test forces TCP via `dig +tcp`, which bypasses the udp_sendmsg kprobe
// entirely. Without the tcp_connect kprobe, attribution would be empty.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationTCPDNSAttribution -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationTCPDNSAttribution(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-tcp"
		testTask      = "leitwacht-integ-tcp"
	)

	// Raw TCP DNS query for example.com A, sent via busybox nc to
	// 127.0.0.1:53. nftables DNAT in the container's netns rewrites dst
	// port 53 → 15353 (our proxy). We target 127.0.0.1 because the
	// container has no external route; loopback is always routable.
	//
	// Wire format (31 bytes): 2-byte TCP length prefix (0x001d = 29),
	// then a standard DNS query: header(12) + qname("example.com", 13)
	// + qtype A(2) + qclass IN(2) = 29. All bytes passed as shell
	// printf hex escapes — using a Go raw string so the backslashes
	// pass through unmolested.
	//
	// Why this route instead of dig: apk can't install bind-tools in
	// a netns with no external network, so we can't rely on dig being
	// present. The bytes below prove the tcp_connect kprobe path
	// without needing any extra tooling.
	const tcpScript = `sleep 3 && printf ` +
		`'\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' ` +
		`| nc -w 5 127.0.0.1 53 >/dev/null 2>&1 || true; sleep 120`

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", tcpScript).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	upstreamAddr, stopUpstream := startFakeNXDomainUpstream(t)
	t.Cleanup(stopUpstream)

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{upstreamAddr}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/tcp-dns",
		Action:      "audit", // audit so apk add and dig both succeed
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/tcp-dns",
	}

	if _, err = mgr.Attach(context.Background(), info, pid, pol); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// One raw TCP DNS query; proxy responds or times out within nc's 5s
	// window. A short wait is enough.
	t.Log("waiting for raw TCP DNS query to complete...")
	time.Sleep(8 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	t.Logf("detach: dns_entries=%d", len(result.Stats.DNSActivity))

	var exampleEntry *DNSActivityEntry

	for i := range result.Stats.DNSActivity {
		d := &result.Stats.DNSActivity[i]
		t.Logf("  dns: domain=%s pid=%d comm=%s binary_path=%s",
			d.Domain, d.PID, d.Comm, d.BinaryPath)

		if d.Domain == "example.com" {
			exampleEntry = d
		}
	}

	if exampleEntry == nil {
		t.Fatal("expected example.com in DNS activity — raw TCP DNS query may not have reached the proxy " +
			"(check nftables DNAT for dst=127.0.0.1:53 → :15353)")
	}

	// The critical assertion: the raw TCP DNS bypasses udp_sendmsg
	// entirely. If attribution is populated, the tcp_connect kprobe
	// fired and the BPF hash was written before the proxy's TCP handler
	// looked it up.
	if exampleEntry.PID == 0 || exampleEntry.Comm == "" {
		t.Errorf("expected TCP DNS query to have attribution populated — "+
			"tcp_connect kprobe may not be firing. Got pid=%d comm=%q",
			exampleEntry.PID, exampleEntry.Comm)
	} else {
		t.Logf("SUCCESS: TCP DNS attributed to pid=%d comm=%s (tcp_connect kprobe path working)",
			exampleEntry.PID, exampleEntry.Comm)
	}

	// comm will be "nc" (busybox netcat) since that's what connected.
	if !strings.Contains(exampleEntry.Comm, "nc") {
		t.Logf("note: comm=%q — expected nc but attribution is still valid",
			exampleEntry.Comm)
	}
}

// TestIntegrationSinkholeHit verifies the end-to-end sinkhole path:
// (1) block-mode proxy returns 192.0.2.1 for a denied domain;
// (2) the client attempts to connect to that IP;
// (3) the egress cgroup_skb filter drops the packet, tagged with
//
//	reason=SINKHOLE;
//
// (4) the violation is recorded with action=sinkhole_hit.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationSinkholeHit -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationSinkholeHit(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-sink"
		testTask      = "leitwacht-integ-sink"
		// Two steps:
		// (1) wget blocked.example.com — proxy returns 192.0.2.1. This
		//     records the DNS activity with the sinkhole IP resolved.
		// (2) Explicit nc -z 192.0.2.1:80 — forces a TCP connect to the
		//     sinkhole IP. With the added `ip route add 192.0.2.1 dev
		//     lo`, the SYN is built and reaches the egress cgroup_skb
		//     filter, which drops it with reason=SINKHOLE and emits a
		//     drop_event to the ringbuf. The userspace reader records
		//     the violation.
		sinkScript = "sleep 3 && " +
			"wget -q -O /dev/null --timeout=2 --tries=1 http://blocked.example.com/ >/dev/null 2>&1 || true; " +
			"nc -z -w 2 192.0.2.1 80 >/dev/null 2>&1 || true; " +
			"sleep 120"
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", sinkScript).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	// The container netns has no default route, so connect(192.0.2.1:80)
	// would normally fail with ENETUNREACH before the packet is even
	// built — meaning the egress cgroup_skb filter never sees it and no
	// sinkhole_hit is recorded. Pin the sinkhole IP to loopback so the
	// kernel accepts the connect, builds the packet, and hands it to
	// the egress hook where our filter drops it with reason=SINKHOLE.
	sinkRoute := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "route", "add", SinkholeIPv4, "dev", "lo")
	if out, routeErr := sinkRoute.CombinedOutput(); routeErr != nil {
		t.Fatalf("add sinkhole route: %v\n%s", routeErr, out)
	}

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	// Block mode policy — nothing allowed. blocked.example will be
	// sinkholed to 192.0.2.1; the connect attempt will be dropped.
	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/sinkhole",
		Action:      "block",
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/sinkhole",
	}

	if _, err = mgr.Attach(context.Background(), info, pid, pol); err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Log("waiting for wget + nc → sinkhole → drop sequence...")
	time.Sleep(10 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	t.Logf("detach: dns_entries=%d violations=%d", len(result.Stats.DNSActivity), len(result.Stats.Violations))

	// (1) DNS activity recorded as blocked with the sinkhole IP. wget
	// fires both A and AAAA in parallel; activity is bucketed by
	// (domain, qtype) so we get two entries — only the A entry carries
	// the sinkhole IP (sinkholeIPsIfA returns nothing for AAAA). Pick
	// the A entry for the sinkhole-presence check; verify the AAAA
	// entry exists too and is also marked blocked.
	var (
		blockedA    *DNSActivityEntry
		blockedAAAA *DNSActivityEntry
	)

	for i := range result.Stats.DNSActivity {
		d := &result.Stats.DNSActivity[i]
		t.Logf("  dns: domain=%s qtype=%s action=%s ips=%v pid=%d comm=%s binary_path=%q",
			d.Domain, d.QueryType, d.Action, d.ResolvedIPs, d.PID, d.Comm, d.BinaryPath)

		if d.Domain != "blocked.example.com" {
			continue
		}

		switch d.QueryType {
		case "A":
			blockedA = d
		case "AAAA":
			blockedAAAA = d
		}
	}

	if blockedA == nil {
		t.Fatal("expected (blocked.example.com, A) in DNS activity")
	}

	if blockedA.Action != "dns_blocked" {
		t.Errorf("DNS A action = %q, want dns_blocked", blockedA.Action)
	}

	if !containsIP(blockedA.ResolvedIPs, SinkholeIPv4) {
		t.Errorf("expected sinkhole IP %s in A-record ResolvedIPs, got %v",
			SinkholeIPv4, blockedA.ResolvedIPs)
	}

	// AAAA is informational — wget may or may not fire it depending on
	// the libc / busybox build. If it did, assert it's also blocked
	// (with empty ResolvedIPs since we don't sinkhole AAAA).
	if blockedAAAA != nil && blockedAAAA.Action != "dns_blocked" {
		t.Errorf("DNS AAAA action = %q, want dns_blocked", blockedAAAA.Action)
	}

	// (2) Violation(s) recorded as sinkhole_hit with ip=192.0.2.1. The
	// script dials 192.0.2.1:80 twice (wget → blocked.example.com which
	// resolves to the sinkhole, then direct nc), so both wget and nc
	// should appear with their own attribution. Assert all of them have
	// binary_path populated — a partial success (one with path, one
	// without) indicates sk_storage capture is racing against the first
	// connect on some sockets.
	var (
		sinkholeViolation     *Violation
		sinkholeViolationsAll []*Violation
	)

	for i := range result.Stats.Violations {
		v := &result.Stats.Violations[i]
		t.Logf("  viol: ip=%s port=%d action=%s pid=%d comm=%q binary_path=%q",
			v.IP, v.Port, v.Action, v.PID, v.Comm, v.BinaryPath)

		if v.Action == "sinkhole_hit" {
			sinkholeViolation = v
			sinkholeViolationsAll = append(sinkholeViolationsAll, v)
		}
	}

	for _, v := range sinkholeViolationsAll {
		if v.BinaryPath == "" {
			t.Errorf("sinkhole_hit violation for pid=%d comm=%q missing binary_path — "+
				"sk_storage may not have been populated at socket_connect for this "+
				"socket (race between exec and first connect?)", v.PID, v.Comm)
		}
	}

	if sinkholeViolation == nil {
		t.Fatal("expected a sinkhole_hit violation — " +
			"check that the egress filter ran (StartRingbufReader) and " +
			"that the drop_event reason byte decoder is mapping reason=2 correctly")
	}

	if sinkholeViolation.IP != SinkholeIPv4 {
		t.Errorf("sinkhole violation ip = %q, want %q",
			sinkholeViolation.IP, SinkholeIPv4)
	}

	// Packet violations carry full attribution from sk_storage populated
	// at LSM socket_connect. The sinkhole test's culprit is an `nc`
	// invocation against the sinkhole IP, so every field should be
	// populated. Missing pid/comm → drop_event decode or
	// bpf_get_current_* call is wrong. Missing binary_path → the
	// bpf_d_path chain in capture_sock_owner failed, which means the
	// agent is no longer self-contained (falls back to process_info
	// LRU, which can evict on long jobs).
	if sinkholeViolation.PID == 0 || sinkholeViolation.Comm == "" {
		t.Errorf("sinkhole violation missing pid/comm: pid=%d comm=%q — "+
			"drop_event pid/comm capture may be broken",
			sinkholeViolation.PID, sinkholeViolation.Comm)
	}

	if sinkholeViolation.BinaryPath == "" {
		t.Errorf("sinkhole violation missing binary_path — sk_storage capture " +
			"via bpf_get_current_task_btf()->mm->exe_file->f_path may be " +
			"failing. Agent's packet attribution is supposed to be self-" +
			"contained (no process_info LRU dependency).")
	}

	t.Logf("SUCCESS: blocked.example.com → %s → sinkhole_hit violation on %s:%d pid=%d comm=%q binary_path=%q",
		SinkholeIPv4, sinkholeViolation.IP, sinkholeViolation.Port,
		sinkholeViolation.PID, sinkholeViolation.Comm, sinkholeViolation.BinaryPath)
}

// TestIntegrationGlibcUnconnectedUDP exercises the DNS attribution path
// for glibc's res_send(), which uses an unconnected UDP socket and
// autobinds mid-sendmsg. A kprobe at udp_sendmsg entry sees src_port=0
// for every first send on such a socket — the whole point of moving
// to fexit is that autobind has committed by return time.
//
// Alpine/musl (used by the other burst test) happens to work with the
// entry kprobe because musl's resolver connect()s before send(),
// autobinding via connect() rather than sendmsg. Most production CI
// traffic (Go toolchain, pip, npm, apt, curl via getaddrinfo) runs
// through glibc, so the entry kprobe silently lost attribution on
// every such query under the entry-kprobe attribution path.
//
//	Run: sudo -E go test ./agentcore/enforcer/ -tags integration \
//	     -run TestIntegrationGlibcUnconnectedUDP -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationGlibcUnconnectedUDP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	const (
		// Debian-slim ships glibc and `getent`. `getent hosts` runs
		// getaddrinfo() → __res_send() which sendto()s on an
		// unconnected UDP socket — the exact path the renovate log
		// showed silently losing attribution.
		testImage     = "docker.io/library/debian:stable-slim"
		testContainer = "leitwacht-integ-glibc"
		testTask      = "leitwacht-integ-glibc"
		burstCount    = 100
		// `ctr run` doesn't provision /etc/resolv.conf. glibc refuses
		// to send DNS without a configured nameserver, so we write one.
		// 127.0.0.1 specifically: the agent's nftables DNAT rewrites
		// (udp/tcp dport 53, daddr 127.0.0.1) → :15353 (proxy). An
		// arbitrary public IP wouldn't route — loopback is the only
		// interface up in this netns.
		burstScript = "sleep 3 && " +
			"echo 'nameserver 127.0.0.1' > /etc/resolv.conf && " +
			"for i in $(seq 1 100); do " +
			"  getent hosts glibc-test-$i.burst.example >/dev/null 2>&1; " +
			"done; " +
			"sleep 120"
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", burstScript).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")

	loOut, loErr := lo.CombinedOutput()
	if loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	platform := &LinuxPlatform{Logger: logger}
	upstreamAddr, stopUpstream := startFakeNXDomainUpstream(t)
	t.Cleanup(stopUpstream)

	mgr := NewManager(logger, 32, []string{upstreamAddr}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/glibc",
		Action:      "audit",
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/glibc",
	}

	_, err = mgr.Attach(context.Background(), info, pid, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Log("waiting for glibc burst to finish (up to 45s)...")
	time.Sleep(45 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	// Collect every burst entry with the signals we can pull from the
	// aggregated DNSActivity record. On a miss we want enough context to
	// distinguish the competing hypotheses: fexit-vs-receive race (misses
	// scattered uniformly or bunched at the burst head), map pressure
	// (misses bunched at the tail), A/AAAA split where one half is
	// attributed and the other isn't (unattributed entries show
	// QueryCount=1 instead of 2), or an empty-answer pattern suggesting
	// the miss correlates with a retry/timeout.
	type burstEntry struct {
		domain      string
		index       int // parsed N from "glibc-test-N.burst.example"; -1 on parse failure
		queryCount  int64
		resolvedIPs int
		pid         uint32
		comm        string
		firstSeen   time.Time
	}

	var (
		burstStart      time.Time
		entries         []burstEntry
		queryCountHisto = map[int64]int{}
	)

	for _, d := range result.Stats.DNSActivity {
		if !strings.Contains(d.Domain, "burst.example") {
			continue
		}

		idx := -1
		if _, err := fmt.Sscanf(d.Domain, "glibc-test-%d.burst.example", &idx); err != nil {
			idx = -1
		}

		entries = append(entries, burstEntry{
			domain:      d.Domain,
			index:       idx,
			queryCount:  d.QueryCount,
			resolvedIPs: len(d.ResolvedIPs),
			pid:         d.PID,
			comm:        d.Comm,
			firstSeen:   d.FirstSeen,
		})

		queryCountHisto[d.QueryCount]++

		if burstStart.IsZero() || d.FirstSeen.Before(burstStart) {
			burstStart = d.FirstSeen
		}
	}

	total := len(entries)
	attributed := 0
	unattributedQCHisto := map[int64]int{}

	var unattributedIndices []int

	for _, e := range entries {
		if e.pid != 0 && e.comm != "" {
			attributed++

			continue
		}

		unattributedQCHisto[e.queryCount]++

		if e.index >= 0 {
			unattributedIndices = append(unattributedIndices, e.index)
		}
	}

	t.Logf("glibc burst result: %d/%d queries attributed (%.1f%%), %d total dns entries",
		attributed, total, float64(attributed)*100/float64(max(total, 1)), len(result.Stats.DNSActivity))
	t.Logf("query_count histogram across all burst entries: %v "+
		"(glibc issues A+AAAA per getent → expect count=2; count=1 means one half never reached the proxy)",
		queryCountHisto)

	if total-attributed > 0 {
		sort.Ints(unattributedIndices)
		t.Logf("unattributed indices (sorted, N/%d): %v", burstCount, unattributedIndices)
		t.Logf("unattributed query_count histogram: %v (compare to overall histogram above)",
			unattributedQCHisto)

		detailCap := 10
		if detailCap > total-attributed {
			detailCap = total - attributed
		}

		t.Logf("unattributed detail (first %d):", detailCap)

		dumped := 0

		for _, e := range entries {
			if dumped >= detailCap {
				break
			}

			if e.pid != 0 && e.comm != "" {
				continue
			}

			offset := e.firstSeen.Sub(burstStart).Seconds()
			t.Logf("  idx=%d domain=%s qcount=%d ips=%d first_seen=+%.3fs pid=%d comm=%q",
				e.index, e.domain, e.queryCount, e.resolvedIPs, offset, e.pid, e.comm)

			dumped++
		}

		// Baseline: log 3 attributed entries in the same shape so the
		// miss pattern is comparable against what "normal" looks like in
		// this run (kernel/glibc combo varies).
		t.Logf("attributed baseline (first 3):")

		shown := 0
		for _, e := range entries {
			if shown >= 3 {
				break
			}

			if e.pid == 0 || e.comm == "" {
				continue
			}

			offset := e.firstSeen.Sub(burstStart).Seconds()
			t.Logf("  idx=%d domain=%s qcount=%d ips=%d first_seen=+%.3fs pid=%d comm=%q",
				e.index, e.domain, e.queryCount, e.resolvedIPs, offset, e.pid, e.comm)

			shown++
		}
	}

	if total < burstCount/2 {
		t.Fatalf("only %d of expected ~%d burst queries recorded — burst script may have failed", total, burstCount)
	}

	// ≥99% attribution. With the fexit hook and glibc's unconnected
	// sendto(), every successful send should capture skc_num after
	// autobind. An entry kprobe on udp_sendmsg would score ~0% here —
	// every first-sendmsg on a fresh unconnected socket hits the
	// src_port==0 skip.
	minRatio := 0.99
	actualRatio := float64(attributed) / float64(total)
	if actualRatio < minRatio {
		t.Errorf("glibc attribution ratio %.2f%% below threshold %.0f%% — udp_sendmsg hook likely placed at entry instead of fexit, "+
			"or autobind runs later than expected on this kernel",
			actualRatio*100, minRatio*100)
	}
}

// TestIntegrationMultiNetnsPortCollision exercises the cross-netns
// port-collision case that motivated keying the attribution map on
// (netns_cookie, src_port) instead of src_port alone.
//
// Setup: two alpine containers in separate network namespaces, each
// with its ephemeral port range shrunk to a 20-port window so the two
// netns deterministically overlap on src_port during a DNS burst.
//
// With the pre-fix port-only key, the second container's writes would
// overwrite the first's, halving the joint attribution ratio. With the
// netns-cookie-keyed map, both containers' entries coexist and both
// observe ~100% attribution.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration \
//
//	-run TestIntegrationMultiNetnsPortCollision -v -count=1.
//
//nolint:cyclop,funlen // integration test with sequential setup steps
func TestIntegrationMultiNetnsPortCollision(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookErr := exec.LookPath("ctr")
	if lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	const (
		testImage  = "docker.io/library/alpine:latest"
		container1 = "leitwacht-integ-collide-1"
		container2 = "leitwacht-integ-collide-2"
		burstCount = 80
		// 8-second initial sleep gives the test harness time to nsenter
		// into each container's netns (from the host, where we have
		// CAP_NET_ADMIN) and narrow ip_local_port_range to a 20-port
		// window. 80 queries then cycle ports multiple times, forcing
		// the two netns to overlap on src_port repeatedly.
		burstScript = "sleep 8; " +
			"for i in $(seq 1 80); do " +
			"  nslookup test-$i.collide.example 2>/dev/null >/dev/null; " +
			"done; sleep 120"
	)

	for _, c := range []string{container1, container2} {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", c).Run()
		_ = exec.Command("ctr", "task", "delete", c).Run()
		_ = exec.Command("ctr", "container", "delete", c).Run()
	}

	_ = exec.Command("ctr", "image", "pull", testImage).Run()

	for _, c := range []string{container1, container2} {
		out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, c,
			"sh", "-c", burstScript).CombinedOutput()
		if err != nil {
			t.Fatalf("ctr run %s: %v\n%s", c, err, out)
		}
	}

	t.Cleanup(func() {
		for _, c := range []string{container1, container2} {
			_ = exec.Command("ctr", "task", "kill", "-s", "9", c).Run()
			time.Sleep(100 * time.Millisecond)
			_ = exec.Command("ctr", "task", "delete", c).Run()
			_ = exec.Command("ctr", "container", "delete", c).Run()
		}
	})

	pid1 := getTaskPID(t, container1)
	pid2 := getTaskPID(t, container2)

	t.Logf("container PIDs: %d %d", pid1, pid2)

	for _, pid := range []int{pid1, pid2} {
		lo := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
			"ip", "link", "set", "lo", "up")
		if out, err := lo.CombinedOutput(); err != nil {
			t.Fatalf("loopback up for pid=%d: %v\n%s", pid, err, out)
		}

		// Narrow ephemeral port range in the container's netns (per-netns
		// sysctl, writable from the host's root user namespace). 20-port
		// window across 2 netns + 80 queries each forces overlapping
		// src_ports between the two containers, which is exactly the
		// scenario that would overwrite entries under a port-only key.
		rng := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
			"sh", "-c", "echo '40000 40020' > /proc/sys/net/ipv4/ip_local_port_range")
		if out, err := rng.CombinedOutput(); err != nil {
			t.Fatalf("narrow port range for pid=%d: %v\n%s", pid, err, out)
		}
	}

	upstreamAddr, stopUpstream := startFakeNXDomainUpstream(t)
	t.Cleanup(stopUpstream)

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{upstreamAddr}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err := mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err := mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/collide",
		Action:      "audit",
	}
	pol.BuildLookups()

	info1 := ContainerInfo{ContainerID: container1 + "000", ProjectPath: "test/collide"}
	info2 := ContainerInfo{ContainerID: container2 + "000", ProjectPath: "test/collide"}

	_, err := mgr.Attach(context.Background(), info1, pid1, pol)
	if err != nil {
		t.Fatalf("attach c1: %v", err)
	}

	_, err = mgr.Attach(context.Background(), info2, pid2, pol)
	if err != nil {
		t.Fatalf("attach c2: %v", err)
	}

	t.Log("both containers attached, waiting for concurrent burst (up to 45s)...")
	time.Sleep(45 * time.Second)

	r1 := mgr.Detach(info1.ContainerID)
	r2 := mgr.Detach(info2.ContainerID)

	if r1 == nil || r2 == nil {
		t.Fatal("expected non-nil detach results")
	}

	count := func(result *DetachResult, label string) (total, attributed int) {
		for _, d := range result.Stats.DNSActivity {
			if !strings.Contains(d.Domain, "collide.example") {
				continue
			}

			total++

			if d.PID != 0 && d.Comm != "" {
				attributed++
			}
		}

		t.Logf("%s: %d/%d burst queries attributed", label, attributed, total)

		return total, attributed
	}

	t1, a1 := count(r1, "c1")
	t2, a2 := count(r2, "c2")

	if t1 < burstCount/2 || t2 < burstCount/2 {
		t.Fatalf("burst didn't produce enough queries: c1=%d c2=%d", t1, t2)
	}

	// With netns-cookie keying, both containers should reach ≥99%
	// attribution despite port overlap. Under the old port-only key, the
	// second-written container would overwrite the first and joint
	// attribution would drop noticeably below 100%.
	//
	// Why collision is guaranteed (rather than tested): with each netns
	// constrained to 21 ports (40000-40020) and 80 sequential nslookups
	// per container, both netns are forced through the same finite set
	// of src_ports ~4 times each. Sequential ephemeral allocation in
	// the kernel makes the two netns walk identical port sequences
	// from similar starts. Verifying overlap directly would require
	// dumping the dns_pid_attribution map (which the test framework
	// doesn't currently expose); the port-range constraint makes
	// collision a property of the workload, not a stochastic outcome.
	const minRatio = 0.99

	if ratio := float64(a1) / float64(t1); ratio < minRatio {
		t.Errorf("c1 attribution %.1f%% below threshold %.0f%% — netns key collision suspected",
			ratio*100, minRatio*100)
	}

	if ratio := float64(a2) / float64(t2); ratio < minRatio {
		t.Errorf("c2 attribution %.1f%% below threshold %.0f%% — netns key collision suspected",
			ratio*100, minRatio*100)
	}
}

func getTaskPID(t *testing.T, taskName string) int {
	t.Helper()

	out, err := exec.Command("ctr", "task", "ls").CombinedOutput()
	if err != nil {
		t.Fatalf("ctr task ls: %v\n%s", err, out)
	}

	var pid int

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, taskName) {
			_, scanErr := fmt.Sscanf(line, "%s %d", new(string), &pid)
			if scanErr != nil {
				t.Fatalf("parse pid from %q: %v", line, scanErr)
			}

			break
		}
	}

	if pid == 0 {
		t.Fatalf("could not find PID for task %s", taskName)
	}

	return pid
}

// startFakeNXDomainUpstream binds a host-loopback UDP listener that
// answers every incoming DNS query with NXDOMAIN. Used by burst-style
// integration tests (AttributionBurst, GlibcUnconnectedUDP,
// MultiNetnsPortCollision) to remove 1.1.1.1's rate-limit + latency
// variance from the assertion path: those tests stress-test the proxy's
// PID-attribution map and the DNS-PID kprobe, which doesn't depend on
// the upstream actually resolving anything. The previous configuration
// flaked when 1.1.1.1 throttled a 500-query NXDOMAIN burst, masking the
// thing the test is actually meant to measure.
//
// Returns the host:port of the listener and a stop function to call
// from t.Cleanup.
func startFakeNXDomainUpstream(t *testing.T) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind fake upstream: %v", err)
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		buf := make([]byte, 1024)

		for {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}

			var req dns.Msg

			unpackErr := req.Unpack(buf[:n])
			if unpackErr != nil {
				continue
			}

			resp := new(dns.Msg)
			resp.SetReply(&req)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true

			packed, packErr := resp.Pack()
			if packErr != nil {
				continue
			}

			_, _ = pc.WriteTo(packed, addr)
		}
	})

	stop := func() {
		_ = pc.Close()
		wg.Wait()
	}

	return pc.LocalAddr().String(), stop
}

// TestIntegrationBareIPBlocked verifies the eBPF default-deny path:
// an attacker that bypasses DNS entirely and connects directly to a
// hardcoded IP must still be dropped because the egress cgroup_skb
// filter rejects anything not in the allow map (which only gets
// populated when the DNS proxy allows a domain).
//
// This is the case where domain-level rules alone wouldn't help —
// nothing is feeding the destination IP into the allow map, so the
// default `return 0; /* default: block */` in egress.c catches it.
//
// The test pins 198.51.100.1 (TEST-NET-2) to the container's loopback
// so the kernel actually builds and dispatches the SYN, giving the
// egress filter something to drop. Otherwise connect() fails with
// ENETUNREACH before the cgroup_skb hook runs and we'd get no
// violation event at all (which would FALSELY pass).
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationBareIPBlocked -v -count=1.
//
//nolint:cyclop // integration test with sequential setup steps
func TestIntegrationBareIPBlocked(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	if _, lookErr := exec.LookPath("ctr"); lookErr != nil {
		t.Skip("ctr not found, requires containerd")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const (
		testImage     = "docker.io/library/alpine:latest"
		testContainer = "leitwacht-integ-bareip"
		testTask      = "leitwacht-integ-bareip"
		// TEST-NET-2 (RFC 5737) — never routed on the public internet,
		// so we don't accidentally smoke-test someone else's IP. Picked
		// outside both the sinkhole (192.0.2.0/24) and the allow map.
		bareIP = "198.51.100.1"
		// nc -z dials TCP and exits — confirms the cgroup_skb filter
		// dropped the SYN. We don't go through DNS at all (no wget,
		// no nslookup) so the only thing that can block this is the
		// default-deny on the egress map.
		bareScript = "sleep 3 && " +
			"nc -z -w 2 " + bareIP + " 80 >/dev/null 2>&1 || true; " +
			"sleep 120"
	)

	_ = exec.Command("ctr", "image", "pull", testImage).Run()
	_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
	_ = exec.Command("ctr", "task", "delete", testTask).Run()
	_ = exec.Command("ctr", "container", "delete", testContainer).Run()

	out, err := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, testContainer,
		"sh", "-c", bareScript).CombinedOutput()
	if err != nil {
		t.Fatalf("ctr run: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("ctr", "task", "kill", "-s", "9", testTask).Run()
		time.Sleep(100 * time.Millisecond)
		_ = exec.Command("ctr", "task", "delete", testTask).Run()
		_ = exec.Command("ctr", "container", "delete", testContainer).Run()
	})

	pid := getTaskPID(t, testTask)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	t.Logf("container PID: %d", pid)

	loUp := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "link", "set", "lo", "up")
	if loOut, loErr := loUp.CombinedOutput(); loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	bareRoute := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid),
		"ip", "route", "add", bareIP, "dev", "lo")
	if out, routeErr := bareRoute.CombinedOutput(); routeErr != nil {
		t.Fatalf("add bare-IP route: %v\n%s", routeErr, out)
	}

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err = mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	if err = mgr.StartCredwatch(); err != nil {
		t.Fatalf("start credwatch: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
	})

	// Block-mode policy. No allow rules, no deny IPs (the bare IP must
	// be caught by the eBPF default-deny, not by an explicit deny entry).
	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/bareip",
		Action:      "block",
	}
	pol.BuildLookups()

	info := ContainerInfo{
		ContainerID: testContainer + "000",
		ProjectPath: "test/bareip",
	}

	if _, err = mgr.Attach(context.Background(), info, pid, pol); err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Log("waiting for nc → bare-IP → eBPF drop sequence...")
	time.Sleep(10 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	t.Logf("detach: dns_entries=%d violations=%d",
		len(result.Stats.DNSActivity), len(result.Stats.Violations))

	// (1) Crucial negative assertion: there must be NO DNS activity
	// referencing the bare IP. If DNS activity for 198.51.100.1
	// somehow shows up, the test is exercising the wrong path (the
	// container resolved through us, which means the allow map
	// learned about the IP via DNS, not via default-deny).
	for _, d := range result.Stats.DNSActivity {
		t.Logf("  dns: domain=%s qtype=%s action=%s ips=%v",
			d.Domain, d.QueryType, d.Action, d.ResolvedIPs)

		if containsIP(d.ResolvedIPs, bareIP) {
			t.Errorf("unexpected DNS activity for %s — the bare-IP path "+
				"should not pass through the DNS proxy at all", bareIP)
		}
	}

	// (2) Positive: a packet-layer violation against the bare IP.
	// The action should be packet_dropped (or similar packet-layer
	// tag) — NOT a dns_* tag, because no DNS event was involved.
	var bareViolation *Violation

	for i := range result.Stats.Violations {
		v := &result.Stats.Violations[i]
		t.Logf("  viol: ip=%s port=%d action=%s pid=%d comm=%q binary_path=%q",
			v.IP, v.Port, v.Action, v.PID, v.Comm, v.BinaryPath)

		if v.IP == bareIP {
			bareViolation = v
		}
	}

	if bareViolation == nil {
		t.Fatal("expected a packet-layer violation against " + bareIP +
			" — the eBPF default-deny did not catch the bare-IP egress, " +
			"or the egress filter wasn't attached to the container's cgroup")
	}

	// The action must be a packet-layer tag, not dns_*. dns_* would
	// indicate the proxy intercepted, which is not the path under test.
	switch bareViolation.Action {
	case "packet_dropped", "sinkhole_hit", "packet_observed":
		// expected — packet-layer tag.
	default:
		t.Errorf("bare-IP violation action = %q, want a packet-layer tag "+
			"(packet_dropped / packet_observed / sinkhole_hit) — dns_* "+
			"would mean DNS proxy was involved, but this test bypassed DNS",
			bareViolation.Action)
	}

	// QueryType must be empty for packet-layer events.
	if bareViolation.QueryType != "" {
		t.Errorf("bare-IP violation has query_type=%q, want empty "+
			"(packet-layer events have no associated DNS query)",
			bareViolation.QueryType)
	}

	// Attribution: PID + comm + binary_path should all be populated
	// from sk_storage at LSM socket_connect time.
	if bareViolation.PID == 0 || bareViolation.Comm == "" {
		t.Errorf("bare-IP violation missing attribution: pid=%d comm=%q",
			bareViolation.PID, bareViolation.Comm)
	}

	if bareViolation.BinaryPath == "" {
		t.Error("bare-IP violation missing binary_path — sk_storage capture failed")
	}
}
