//go:build linux

package enforcer

import (
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// TestDefenseInDepth_ProcMemKill verifies that the proc_mem LSM denies
// /proc/*/mem reads for monitored containers and emits a ringbuf event.
//
//	Run: sudo -E go test ./agentcore/enforcer/ -run TestDefenseInDepth_ProcMemKill -v -count=1
func TestDefenseInDepth_ProcMemKill(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Load proc_mem LSM directly
	objs, lsmLink, err := loadProcMemLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	// 2. Start ringbuf reader
	var mu sync.Mutex
	var events []procMemEventBPF

	stop, err := startProcMemReader(objs, logger, func(evt procMemEventBPF) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
		t.Logf("RINGBUF: cgroup=%d pid=%d comm=%s path=%s",
			evt.CgroupID, evt.PID, nullTerminated(evt.Comm[:]), nullTerminated(evt.Path[:]))
	})
	if err != nil {
		t.Fatalf("startProcMemReader: %v", err)
	}
	defer stop()

	// 3. Add our cgroup as monitored
	myCgroupPath, err := getCgroupPath(os.Getpid())
	if err != nil {
		t.Fatalf("get cgroup path: %v", err)
	}

	var st syscall.Stat_t

	err = syscall.Stat(myCgroupPath, &st)
	if err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	myCgroupID := st.Ino

	err = objs.KnownContainers.Put(myCgroupID, cgroupProcConfig{Flags: procMemFlagMonitored})
	if err != nil {
		t.Fatalf("put known_containers: %v", err)
	}
	defer objs.KnownContainers.Delete(myCgroupID) //nolint:errcheck // test cleanup

	// 4. Attempt to read /proc/self/mem — expect EPERM + ringbuf event
	f, err := os.Open("/proc/self/mem")
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open /proc/self/mem to fail with EPERM, but it succeeded")
	}

	if !os.IsPermission(err) {
		t.Fatalf("expected permission error, got: %v", err)
	}

	t.Log("EPERM received for /proc/self/mem open")

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	eventCount := len(events)
	mu.Unlock()

	if eventCount == 0 {
		t.Fatal("no proc_mem ringbuf events received despite EPERM")
	}

	t.Logf("proc_mem kill path verified: %d event(s)", eventCount)
}

// TestDefenseInDepth_CredwatchKill verifies that the credwatch LSM denies
// credential file reads for monitored containers and emits a ringbuf event.
//
//	Run: sudo -E go test ./agentcore/enforcer/ -run TestDefenseInDepth_CredwatchKill -v -count=1
func TestDefenseInDepth_CredwatchKill(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Load credwatch LSM
	objs, lsmLink, err := loadCredwatchLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	// 2. Populate watched path maps with a test suffix
	err = populateWatchedPathMaps(objs, []string{"/.ssh/id_rsa"}, nil)
	if err != nil {
		t.Fatalf("populateWatchedPathMaps: %v", err)
	}

	// 3. Start ringbuf reader
	var mu sync.Mutex
	var events []credwatchEventBPF

	stop, err := startCredwatchReader(objs, logger, func(evt credwatchEventBPF) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
		t.Logf("RINGBUF: cgroup=%d pid=%d comm=%s path=%s",
			evt.CgroupID, evt.PID, nullTerminated(evt.Comm[:]), nullTerminated(evt.Path[:]))
	})
	if err != nil {
		t.Fatalf("startCredwatchReader: %v", err)
	}
	defer stop()

	// 4. Create a real file at a path matching the watched suffix
	//    (before adding our cgroup to the monitored map, so the WriteFile
	//    open doesn't get blocked by the LSM we just loaded)
	tmpDir := t.TempDir()
	sshDir := tmpDir + "/.ssh"

	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	keyFile := sshDir + "/id_rsa"
	if err := os.WriteFile(keyFile, []byte("fake-key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// 5. Add our cgroup as monitored (after file creation so WriteFile isn't blocked)
	myCgroupPath, err := getCgroupPath(os.Getpid())
	if err != nil {
		t.Fatalf("get cgroup path: %v", err)
	}

	var st syscall.Stat_t

	err = syscall.Stat(myCgroupPath, &st)
	if err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	myCgroupID := st.Ino

	err = populateCredwatchMaps(objs, myCgroupID, false, false)
	if err != nil {
		t.Fatalf("populateCredwatchMaps: %v", err)
	}
	defer removeCredwatchMaps(objs, myCgroupID)

	// 6. Attempt to open the key file — expect EPERM + ringbuf event
	f, err := os.Open(keyFile)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open of id_rsa to fail with EPERM, but it succeeded")
	}

	if !os.IsPermission(err) {
		t.Fatalf("expected permission error, got: %v", err)
	}

	t.Log("EPERM received for .ssh/id_rsa open")

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	eventCount := len(events)
	mu.Unlock()

	if eventCount == 0 {
		t.Fatal("no credwatch ringbuf events received despite EPERM")
	}

	// Verify the path in the event ends with the watched suffix
	mu.Lock()
	if len(events) > 0 {
		path := nullTerminated(events[0].Path[:])
		if !endsWith(path, "/.ssh/id_rsa") {
			t.Errorf("path = %q, want suffix /.ssh/id_rsa", path)
		}
	}
	mu.Unlock()

	t.Logf("credwatch kill path verified: %d event(s)", eventCount)
}

// TestDefenseInDepth_DNSKill verifies that OnDNSViolation fires in block
// mode and does not fire in audit mode. This tests the DNS kill path
// without requiring containerd — it uses HandleDNSQuery directly.
//
//	Run: sudo -E go test ./agentcore/enforcer/ -run TestDefenseInDepth_DNSKill -v -count=1
func TestDefenseInDepth_DNSKill(t *testing.T) {
	// This test does not require root — HandleDNSQuery is pure Go.
	// Included here for completeness alongside the other defense-in-depth tests.

	var violations []struct {
		cgroupID uint64
		domain   string
		action   string
	}

	// Block mode: OnDNSViolation should fire
	blockRec := NewViolationRecorder(nil)
	blockPol := &policy.ResolvedPolicy{
		Action:   policy.ActionBlock,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": {allowFQDN("safe.example.com", 443)}},
	}
	blockCfg := &DNSProxyConfig{
		Policy:         blockPol,
		Upstreams:      []string{testUnroutableUpstream},
		LookupRecorder: func(_ uint64) *ViolationRecorder { return blockRec },
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		AddToAllowMap:  func(_ net.IP, _ []int, _ uint32) error { return nil },
		OnDNSViolation: func(cgroupID uint64, domain, action string) {
			violations = append(violations, struct {
				cgroupID uint64
				domain   string
				action   string
			}{cgroupID: cgroupID, domain: domain, action: action})
		},
	}

	msg := makeQuery("evil.example.com", dns.TypeA)
	_ = HandleDNSQuery(msg, blockCfg, blockPol, blockRec, 0, "", "", "", 42)

	if len(violations) != 1 {
		t.Fatalf("block mode: expected 1 OnDNSViolation call, got %d", len(violations))
	}

	if violations[0].action != "dns_blocked" {
		t.Errorf("action = %q, want dns_blocked", violations[0].action)
	}

	t.Log("DNS kill path fires in block mode")

	// Audit mode: OnDNSViolation should NOT fire
	violations = nil
	auditRec := NewViolationRecorder(nil)
	auditPol := &policy.ResolvedPolicy{
		Action:   policy.ActionAudit,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": {allowFQDN("safe.example.com", 443)}},
	}
	auditCfg := &DNSProxyConfig{
		Policy:         auditPol,
		Upstreams:      []string{testUnroutableUpstream},
		LookupRecorder: func(_ uint64) *ViolationRecorder { return auditRec },
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		AddToAllowMap:  func(_ net.IP, _ []int, _ uint32) error { return nil },
		OnDNSViolation: func(_ uint64, _, _ string) {
			violations = append(violations, struct {
				cgroupID uint64
				domain   string
				action   string
			}{})
		},
	}

	msg = makeQuery("evil.example.com", dns.TypeA)
	_ = HandleDNSQuery(msg, auditCfg, auditPol, auditRec, 0, "", "", "", 42)

	if len(violations) != 0 {
		t.Fatal("audit mode: OnDNSViolation should not fire")
	}

	t.Log("DNS kill path does NOT fire in audit mode")
}

// TestDefenseInDepth_AllThreeKillPoints verifies all three defense-in-depth
// kill points are independently operational via the Manager lifecycle.
// Loads proc_mem + credwatch LSMs, wires OnDNSViolation, and verifies each
// kill path produces the expected event/callback.
//
//	Run: sudo -E go test ./agentcore/enforcer/ -run TestDefenseInDepth_AllThreeKillPoints -v -count=1
//
//nolint:cyclop // integration-style test with sequential kernel setup steps
func TestDefenseInDepth_AllThreeKillPoints(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Set up Manager with all three subsystems
	mgr := NewManager(logger, 32, []string{testUnroutableUpstream}, nil, &LinuxPlatform{Logger: logger},
		CredwatchConfig{
			Enabled:      true,
			WatchedPaths: []string{"/.testcred/secret"},
		},
		ProcMemConfig{Enabled: true},
	)

	if err := mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("StartDNSPIDTracker: %v", err)
	}

	if err := mgr.StartCredwatch(); err != nil {
		mgr.StopDNSPIDTracker()
		t.Fatalf("StartCredwatch: %v", err)
	}

	if err := mgr.StartProcMem(); err != nil {
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
		t.Fatalf("StartProcMem: %v", err)
	}

	if !mgr.CredwatchLSMLoaded() {
		mgr.StopProcMem()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
		t.Skip("credwatch LSM not available")
	}

	if !mgr.ProcMemLSMLoaded() {
		mgr.StopProcMem()
		mgr.StopCredwatch()
		mgr.StopDNSPIDTracker()
		t.Skip("proc_mem LSM not available")
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopCredwatch()
		mgr.StopProcMem()
		mgr.StopDNSPIDTracker()
	})

	// Wire kill callbacks and track events
	var (
		mu            sync.Mutex
		credEvents    []CredwatchEvent
		procMemEvents []ProcMemEvent
		dnsViolations []struct {
			containerID string
			domain      string
			action      string
		}
	)

	mgr.OnCredwatchEvent = func(ev CredwatchEvent) {
		mu.Lock()
		credEvents = append(credEvents, ev)
		mu.Unlock()
		t.Logf("CREDWATCH KILL: container=%s pid=%d path=%s", ev.ContainerID, ev.PID, ev.Path)
	}

	mgr.OnProcMemEvent = func(ev ProcMemEvent) {
		mu.Lock()
		procMemEvents = append(procMemEvents, ev)
		mu.Unlock()
		t.Logf("PROC_MEM KILL: container=%s pid=%d path=%s", ev.ContainerID, ev.PID, ev.Path)
	}

	mgr.SetOnDNSViolation(func(containerID, domain, action string) error {
		mu.Lock()
		dnsViolations = append(dnsViolations, struct {
			containerID string
			domain      string
			action      string
		}{containerID: containerID, domain: domain, action: action})
		mu.Unlock()
		t.Logf("DNS KILL: container=%s domain=%s action=%s", containerID, domain, action)

		return nil
	})

	// Create credential file before registering our cgroup, so the
	// WriteFile open doesn't get blocked by the LSM we just loaded.
	tmpDir := t.TempDir()
	credDir := tmpDir + "/.testcred"

	if err := os.MkdirAll(credDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	credFile := credDir + "/secret"
	if err := os.WriteFile(credFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Attach our cgroup to both LSMs (after file creation)
	myCgroupPath, err := getCgroupPath(os.Getpid())
	if err != nil {
		t.Fatalf("get cgroup path: %v", err)
	}

	mgr.AttachCredwatch("test-container", myCgroupPath, false, false)
	mgr.AttachProcMem("test-container", myCgroupPath, false, false)

	// --- Kill point 1: /proc/self/mem ---
	f, err := os.Open("/proc/self/mem")
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open /proc/self/mem to fail with EPERM")
	}

	if !os.IsPermission(err) {
		t.Fatalf("expected permission error for /proc/self/mem, got: %v", err)
	}

	t.Log("Kill point 1 (proc_mem): EPERM on /proc/self/mem")

	// --- Kill point 2: credential file access ---

	f, err = os.Open(credFile)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open of credential file to fail with EPERM")
	}

	if !os.IsPermission(err) {
		t.Fatalf("expected permission error for credential file, got: %v", err)
	}

	t.Log("Kill point 2 (credwatch): EPERM on .testcred/secret")

	// --- Kill point 3: DNS violation (via Manager callback) ---
	// Simulate a DNS violation by calling the onDNSViolation callback
	// directly (testing the Manager wiring, not the DNS proxy itself).
	if mgr.onDNSViolation != nil {
		_ = mgr.onDNSViolation("test-container", "evil.example.com", "dns_blocked")
	}

	// Wait for ringbuf events
	time.Sleep(500 * time.Millisecond)

	// Verify all three kill points produced events
	mu.Lock()
	defer mu.Unlock()

	if len(procMemEvents) == 0 {
		t.Error("no proc_mem events received — kill point 1 not working")
	} else {
		t.Logf("Kill point 1 verified: %d proc_mem event(s)", len(procMemEvents))
	}

	if len(credEvents) == 0 {
		t.Error("no credwatch events received — kill point 2 not working")
	} else {
		t.Logf("Kill point 2 verified: %d credwatch event(s)", len(credEvents))
	}

	if len(dnsViolations) == 0 {
		t.Error("no DNS violations received — kill point 3 not working")
	} else {
		t.Logf("Kill point 3 verified: %d DNS violation(s)", len(dnsViolations))
	}

	t.Log("=== ALL THREE DEFENSE-IN-DEPTH KILL POINTS VERIFIED ===")
}
