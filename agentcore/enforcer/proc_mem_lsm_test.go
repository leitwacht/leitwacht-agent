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

func TestProcMemLSMLoadAttach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	objs, lsmLink, err := loadProcMemLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	t.Log("proc_mem LSM program loaded and attached successfully")

	// Verify known_containers map is usable with cgroup_proc_config value type
	cgID := uint64(999999)
	cfg := cgroupProcConfig{Flags: procMemFlagMonitored}

	err = objs.KnownContainers.Put(cgID, cfg)
	if err != nil {
		t.Fatalf("put known_containers: %v", err)
	}

	err = objs.KnownContainers.Delete(cgID)
	if err != nil {
		t.Fatalf("delete known_containers: %v", err)
	}

	t.Log("BPF maps verified")
}

func TestProcMemManagerStartStop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	mgr := NewManager(testLogger(), 32, nil, nil, nil, CredwatchConfig{}, ProcMemConfig{
		Enabled: true,
	})

	err := mgr.StartProcMem()
	if err != nil {
		t.Fatalf("StartProcMem: %v", err)
	}

	if !mgr.ProcMemLSMLoaded() {
		t.Skip("eBPF/LSM not available in this environment")
	}

	mgr.StopProcMem()

	if mgr.ProcMemLSMLoaded() {
		t.Fatal("proc_mem LSM should not be loaded after Stop")
	}

	t.Log("Manager StartProcMem/StopProcMem lifecycle verified")
}

// TestProcMemRingbufDirect tests the full BPF flow without Docker:
// loads the LSM, adds the current process's cgroup to the map, tries to
// open /proc/self/mem (expect -EPERM), and checks the ring buffer event.
// Also tests the allow_proc_read exemption.
//
//nolint:cyclop // integration-style test with sequential kernel setup steps
func TestProcMemRingbufDirect(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Load LSM
	objs, lsmLink, err := loadProcMemLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	// 2. Start ring buffer reader
	var mu sync.Mutex
	var events []procMemEventBPF
	stop, err := startProcMemReader(objs, logger, func(evt procMemEventBPF) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
		t.Logf("RINGBUF EVENT: cgroup=%d pid=%d comm=%s path=%s",
			evt.CgroupID, evt.PID, nullTerminated(evt.Comm[:]), nullTerminated(evt.Path[:]))
	})
	if err != nil {
		t.Fatalf("startProcMemReader: %v", err)
	}
	defer stop()

	// 3. Get our own cgroup ID
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

	// 4. Add our cgroup to known_containers (monitored, no exemption)
	err = objs.KnownContainers.Put(myCgroupID, cgroupProcConfig{Flags: procMemFlagMonitored})
	if err != nil {
		t.Fatalf("put known_containers: %v", err)
	}
	defer objs.KnownContainers.Delete(myCgroupID) //nolint:errcheck // test cleanup

	// 5. Try to open /proc/self/mem — expect -EPERM
	t.Log("opening /proc/self/mem (expect EPERM)...")
	f, err := os.Open("/proc/self/mem")
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open /proc/self/mem to fail with EPERM, but it succeeded")
	}
	t.Logf("open result: %v", err)

	if !os.IsPermission(err) {
		t.Fatalf("expected permission error, got: %v", err)
	}
	t.Log("got EPERM as expected")

	// 6. Wait for ring buffer event
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	eventCount := len(events)
	mu.Unlock()

	if eventCount == 0 {
		info, _ := objs.ProcMemEvents.Info()
		t.Logf("ringbuf map info: %+v", info)
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

	// Path should end with /mem
	if len(path) < 4 || path[len(path)-4:] != "/mem" {
		t.Errorf("path = %q, want suffix /mem", path)
	}

	t.Log("=== PROC_MEM DENY TEST PASSED ===")

	// 7. Test allow_proc_read exemption: update map with exemption flag,
	// then open /proc/self/mem again — should succeed this time.
	mu.Lock()
	events = nil
	mu.Unlock()

	err = objs.KnownContainers.Put(myCgroupID, cgroupProcConfig{
		Flags: procMemFlagMonitored | procMemFlagAllowProcRead,
	})
	if err != nil {
		t.Fatalf("put known_containers (exempt): %v", err)
	}

	t.Log("opening /proc/self/mem with allow_proc_read exemption (expect success)...")
	f, err = os.Open("/proc/self/mem")
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err != nil {
		t.Fatalf("expected open /proc/self/mem to succeed with exemption, got: %v", err)
	}
	t.Log("open succeeded with exemption as expected")

	// 8. No ring buffer event should be emitted for the exempted open
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	exemptEventCount := len(events)
	mu.Unlock()

	if exemptEventCount != 0 {
		t.Fatalf("expected 0 ring buffer events with allow_proc_read, got %d", exemptEventCount)
	}

	t.Log("=== PROC_MEM EXEMPTION TEST PASSED ===")
}
