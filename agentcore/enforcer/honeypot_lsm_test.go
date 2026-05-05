//go:build linux

package enforcer

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestHoneypotLSMLoadAttach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	objs, lsmLink, err := loadHoneypotLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	t.Log("LSM program loaded and attached successfully")

	// Verify maps exist and are usable
	cgID := uint64(999999)

	err = objs.KnownContainers.Put(cgID, uint8(1))
	if err != nil {
		t.Fatalf("put known_containers: %v", err)
	}

	err = objs.KnownContainers.Delete(cgID)
	if err != nil {
		t.Fatalf("delete known_containers: %v", err)
	}

	key := honeypotKey{Dev: 1, Ino: 12345}

	err = objs.HoneypotInodes.Put(key, uint8(1))
	if err != nil {
		t.Fatalf("put honeypot_inodes: %v", err)
	}

	err = objs.HoneypotInodes.Delete(key)
	if err != nil {
		t.Fatalf("delete honeypot_inodes: %v", err)
	}

	t.Log("BPF maps verified")
}

func TestHoneypotManagerStartStop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	// Create a temp dir with a fake honeypot file
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "credentials"), []byte("decoy"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	mgr := NewManager(testLogger(), 32, nil, nil, nil, HoneypotConfig{
		Enabled: true,
		Dir:     dir,
	})

	err = mgr.StartHoneypot()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if !mgr.LSMLoaded() {
		t.Skip("eBPF/LSM not available in this environment")
	}

	mgr.StopHoneypot()

	if mgr.LSMLoaded() {
		t.Fatal("LSM should not be loaded after Stop")
	}

	t.Log("Manager Start/Stop lifecycle verified")
}

// TestHoneypotRingbufDirect tests the full BPF flow without Docker:
// loads the LSM, adds the current process's cgroup to the map, stats a file,
// adds its inode, tries to open it (expect -EPERM), and checks ring buffer.
//
//nolint:cyclop // integration-style test with sequential kernel setup steps
func TestHoneypotRingbufDirect(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Create a honeypot file
	dir := t.TempDir()
	honeypotFile := filepath.Join(dir, "credentials")
	err := os.WriteFile(honeypotFile, []byte("decoy"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Load LSM
	objs, lsmLink, err := loadHoneypotLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup
	defer objs.Close()    //nolint:errcheck // test cleanup

	// 3. Start ring buffer reader
	var mu sync.Mutex
	var events []honeypotEventBPF
	stop, err := startHoneypotReader(objs, logger, func(evt honeypotEventBPF) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
		t.Logf("RINGBUF EVENT: cgroup=%d pid=%d dev=%d ino=%d comm=%s",
			evt.CgroupID, evt.PID, evt.Dev, evt.Ino, nullTerminated(evt.Comm[:]))
	})
	if err != nil {
		t.Fatalf("startHoneypotReader: %v", err)
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

	// 5. Add our cgroup to known_containers
	err = objs.KnownContainers.Put(myCgroupID, uint8(1))
	if err != nil {
		t.Fatalf("put known_containers: %v", err)
	}
	defer objs.KnownContainers.Delete(myCgroupID) //nolint:errcheck // test cleanup

	// 6. Stat the honeypot file and add to map
	dev, ino, err := statFile(honeypotFile)
	if err != nil {
		t.Fatalf("statFile: %v", err)
	}
	t.Logf("honeypot file: dev=%d ino=%d", dev, ino)

	key := honeypotKey{Dev: dev, Ino: ino}

	err = objs.HoneypotInodes.Put(key, uint8(1))
	if err != nil {
		t.Fatalf("put honeypot_inodes: %v", err)
	}
	defer objs.HoneypotInodes.Delete(key) //nolint:errcheck // test cleanup

	// 7. Try to open the honeypot file — expect -EPERM
	t.Log("opening honeypot file (expect EPERM)...")
	f, err := os.Open(honeypotFile)
	if f != nil {
		f.Close() //nolint:errcheck // test cleanup
	}

	if err == nil {
		t.Fatal("expected open to fail with EPERM, but it succeeded")
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
		// Extra debugging: try reading the ring buffer map info
		info, _ := objs.HoneypotEvents.Info()
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
	if evt.Dev != dev {
		t.Errorf("dev = %d, want %d", evt.Dev, dev)
	}
	if evt.Ino != ino {
		t.Errorf("ino = %d, want %d", evt.Ino, ino)
	}
	comm := nullTerminated(evt.Comm[:])
	t.Logf("comm = %q, pid = %d", comm, evt.PID)
	if evt.PID == 0 {
		t.Error("pid should be non-zero")
	}

	t.Log("=== HONEYPOT RINGBUF TEST PASSED ===")
}
