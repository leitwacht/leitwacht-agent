//go:build linux

package enforcer

import (
	"log/slog"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestCredwatchLSMLoadAttach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	objs, lsmLink, err := loadCredwatchLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	t.Log("credwatch LSM program loaded and attached successfully")

	// Verify known_containers map is usable with cgroup_credwatch_config value type
	cgID := uint64(999999)
	cfg := cgroupCredwatchConfig{Flags: credwatchFlagMonitored}

	err = objs.KnownContainers.Put(cgID, cfg)
	if err != nil {
		t.Fatalf("put known_containers: %v", err)
	}

	err = objs.KnownContainers.Delete(cgID)
	if err != nil {
		t.Fatalf("delete known_containers: %v", err)
	}

	// Verify watched_suffixes and watched_filenames maps are usable
	var suffixKey [64]byte
	copy(suffixKey[:], "/.ssh/id_rsa")

	err = objs.WatchedSuffixes.Put(suffixKey[:], uint8(1))
	if err != nil {
		t.Fatalf("put watched_suffixes: %v", err)
	}

	err = objs.WatchedSuffixes.Delete(suffixKey[:])
	if err != nil {
		t.Fatalf("delete watched_suffixes: %v", err)
	}

	var fnameKey [64]byte
	copy(fnameKey[:], "id_rsa")

	err = objs.WatchedFilenames.Put(fnameKey[:], uint8(1))
	if err != nil {
		t.Fatalf("put watched_filenames: %v", err)
	}

	err = objs.WatchedFilenames.Delete(fnameKey[:])
	if err != nil {
		t.Fatalf("delete watched_filenames: %v", err)
	}

	t.Log("BPF maps verified")
}

func TestCredwatchManagerStartStop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	mgr := NewManager(testLogger(), 32, nil, nil, nil, CredwatchConfig{
		Enabled:      true,
		WatchedPaths: []string{"/.ssh/id_rsa"},
	}, ProcMemConfig{
		Enabled: true,
	})

	err := mgr.StartCredwatch()
	if err != nil {
		t.Fatalf("StartCredwatch: %v", err)
	}

	if !mgr.CredwatchLSMLoaded() {
		t.Skip("eBPF/LSM not available in this environment")
	}

	mgr.StopCredwatch()

	if mgr.CredwatchLSMLoaded() {
		t.Fatal("credwatch LSM should not be loaded after Stop")
	}

	t.Log("Manager StartCredwatch/StopCredwatch lifecycle verified")
}

//nolint:cyclop // integration-style test with sequential kernel setup steps
func TestCredwatchRingbufDirect(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Load LSM
	objs, lsmLink, err := loadCredwatchLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	// 2. Populate watched suffix and filename maps
	err = populateWatchedPathMaps(objs, []string{"/.testcred/secret"}, nil, nil)
	if err != nil {
		t.Fatalf("populateWatchedPathMaps: %v", err)
	}

	// 3. Start ring buffer reader
	var mu sync.Mutex
	var events []credwatchEventBPF
	stop, err := startCredwatchReader(objs, logger, func(evt credwatchEventBPF) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
		t.Logf("RINGBUF EVENT: cgroup=%d pid=%d comm=%s path=%s",
			evt.CgroupID, evt.PID, nullTerminated(evt.Comm[:]), nullTerminated(evt.Path[:]))
	})
	if err != nil {
		t.Fatalf("startCredwatchReader: %v", err)
	}
	defer stop()

	// 4. Get our own cgroup ID
	myCgroupPath, err := getCgroupPath(os.Getpid())
	if err != nil {
		t.Fatalf("get cgroup path: %v", err)
	}
	t.Logf("test process cgroup: %s", myCgroupPath)

	var st syscall.Stat_t

	err = syscall.Stat(myCgroupPath, &st)
	if err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	myCgroupID := st.Ino
	t.Logf("test process cgroup ID: %d", myCgroupID)
	// 5. Create a test credential file at a path matching the watched suffix
	//    (before adding our cgroup, so the WriteFile open doesn't get blocked)
	tmpDir := t.TempDir()
	credDir := tmpDir + "/.testcred"
	if err := os.MkdirAll(credDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	credFile := credDir + "/secret"
	if err := os.WriteFile(credFile, []byte("secret-data"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// 6. Add our cgroup to known_containers (monitored, no exemption)
	err = populateCredwatchMaps(objs, myCgroupID, false, false)
	if err != nil {
		t.Fatalf("populateCredwatchMaps: %v", err)
	}
	defer removeCredwatchMaps(objs, myCgroupID)

	// 7. Try to open the credential file — expect EPERM
	t.Log("opening credential file (expect EPERM)...")
	f, err := os.Open(credFile)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open of credential file to fail with EPERM, but it succeeded")
	}
	t.Logf("open result: %v", err)

	if !os.IsPermission(err) {
		t.Fatalf("expected permission error, got: %v", err)
	}
	t.Log("got EPERM as expected")

	// 8. Wait for ring buffer event
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	eventCount := len(events)
	mu.Unlock()

	if eventCount == 0 {
		t.Fatal("no ring buffer events received despite EPERM")
	}

	t.Logf("received %d ring buffer event(s)", eventCount)

	mu.Lock()
	if len(events) == 0 {
		mu.Unlock()
		t.Fatal("events slice unexpectedly empty after non-zero event count")
	}
	evt := events[0]
	mu.Unlock()

	if evt.CgroupID != myCgroupID {
		t.Errorf("cgroup_id = %d, want %d", evt.CgroupID, myCgroupID)
	}

	path := nullTerminated(evt.Path[:])
	t.Logf("path = %q, comm = %q, pid = %d", path, nullTerminated(evt.Comm[:]), evt.PID)

	if evt.PID == 0 {
		t.Error("pid should be non-zero")
	}

	// Path should end with the watched suffix
	if !endsWith(path, "/.testcred/secret") {
		t.Errorf("path = %q, want suffix /.testcred/secret", path)
	}

	t.Log("=== CREDWATCH DENY TEST PASSED ===")

	// 9. Test allow_credwatch exemption: update map with exemption flag,
	// then open again — should succeed this time.
	mu.Lock()
	events = nil
	mu.Unlock()

	err = populateCredwatchMaps(objs, myCgroupID, true, false)
	if err != nil {
		t.Fatalf("populateCredwatchMaps (exempt): %v", err)
	}

	t.Log("opening credential file with allow_credwatch exemption (expect success)...")
	f, err = os.Open(credFile)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err != nil {
		t.Fatalf("expected open to succeed with exemption, got: %v", err)
	}
	t.Log("open succeeded with exemption as expected")

	// 10. No ring buffer event should be emitted for the exempted open
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	exemptEventCount := len(events)
	mu.Unlock()

	if exemptEventCount != 0 {
		t.Fatalf("expected 0 ring buffer events with allow_credwatch, got %d", exemptEventCount)
	}

	t.Log("=== CREDWATCH EXEMPTION TEST PASSED ===")
}

// endsWith checks if s ends with suffix.
func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
