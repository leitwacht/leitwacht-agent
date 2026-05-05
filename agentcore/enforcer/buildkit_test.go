package enforcer

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func testBuildkitLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestBuildkitAttachDetach(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, HoneypotConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	// Create a buildkit monitor using the fake platform.
	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 0,
		logger:     testBuildkitLogger(),
	}
	mgr.SetBuildkit(bm)

	ctx := context.Background()
	pol := testPolicy("audit")
	info := ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "test/project"}

	e, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	if e == nil {
		t.Fatal("expected non-nil enforcer")
	}

	// Buildkit should be attached to this job.
	if bm.activeJob != "abcdef123456" {
		t.Errorf("buildkit activeJob = %q, want %q", bm.activeJob, "abcdef123456")
	}

	if bm.LookupRecorder() == nil {
		t.Error("buildkit recorder should be set during job")
	}

	// Verify buildkit cgroupID is registered in cgroupRecorders.
	nctx := e.ctx
	nctx.mu.RLock()
	_, hasBK := nctx.cgroupRecorders[bm.CgroupID()]
	nctx.mu.RUnlock()

	if !hasBK {
		t.Error("buildkit cgroupID not registered in cgroupRecorders")
	}

	// Detach.
	result := mgr.Detach("abcdef123456")
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	// Buildkit should be cleared (drain delay = 0).
	if bm.activeJob != "" {
		t.Errorf("buildkit activeJob = %q after detach, want empty", bm.activeJob)
	}

	if bm.LookupRecorder() != nil {
		t.Error("buildkit recorder should be nil after detach")
	}
}

func TestBuildkitDrainDelay(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, HoneypotConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 100 * time.Millisecond,
		logger:     testBuildkitLogger(),
	}
	mgr.SetBuildkit(bm)

	ctx := context.Background()
	pol := testPolicy("audit")
	info := ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "test/project"}

	_, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	mgr.Detach("abcdef123456")

	// Immediately after detach, recorder should still be active (draining).
	if bm.LookupRecorder() == nil {
		t.Error("buildkit recorder should be active during drain")
	}

	// After drain delay, recorder should be cleared.
	time.Sleep(200 * time.Millisecond)

	if bm.LookupRecorder() != nil {
		t.Error("buildkit recorder should be nil after drain delay")
	}

	if bm.activeJob != "" {
		t.Errorf("buildkit activeJob = %q after drain, want empty", bm.activeJob)
	}
}

func TestBuildkitDrainCancelledByNewJob(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, HoneypotConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 500 * time.Millisecond,
		logger:     testBuildkitLogger(),
	}
	mgr.SetBuildkit(bm)

	ctx := context.Background()
	pol := testPolicy("audit")

	// Job 1.
	info1 := ContainerInfo{ContainerID: "container-one1", ProjectPath: "test/project"}
	_, err := mgr.Attach(ctx, info1, 1, pol)
	if err != nil {
		t.Fatalf("attach job 1: %v", err)
	}

	mgr.Detach("container-one1")

	// Job 2 starts during drain — should cancel drain and attach.
	info2 := ContainerInfo{ContainerID: "container-two2", ProjectPath: "test/project"}
	_, err = mgr.Attach(ctx, info2, 2, pol)
	if err != nil {
		t.Fatalf("attach job 2: %v", err)
	}

	if bm.activeJob != "container-two2" {
		t.Errorf("buildkit activeJob = %q, want %q", bm.activeJob, "container-two2")
	}

	if bm.LookupRecorder() == nil {
		t.Error("buildkit recorder should be set for job 2")
	}

	// Wait past the original drain delay — should NOT clear (new job took over).
	time.Sleep(600 * time.Millisecond)

	if bm.activeJob != "container-two2" {
		t.Errorf("buildkit activeJob changed after old drain expired: got %q", bm.activeJob)
	}

	mgr.Detach("container-two2")
}

func TestBuildkitConcurrentGuard(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, HoneypotConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 0,
		logger:     testBuildkitLogger(),
	}
	mgr.SetBuildkit(bm)

	ctx := context.Background()
	pol := testPolicy("audit")

	// Job 1 attaches buildkit.
	info1 := ContainerInfo{ContainerID: "container-one1", ProjectPath: "test/project"}
	_, err := mgr.Attach(ctx, info1, 1, pol)
	if err != nil {
		t.Fatalf("attach job 1: %v", err)
	}

	// Job 2 tries to attach — should be skipped (concurrent guard).
	info2 := ContainerInfo{ContainerID: "container-two2", ProjectPath: "test/project"}
	e2, err := mgr.Attach(ctx, info2, 2, pol)
	if err != nil {
		t.Fatalf("attach job 2: %v", err)
	}

	if e2 == nil {
		t.Fatal("job 2 should still get an enforcer (just no buildkit)")
	}

	// Buildkit should still be attached to job 1.
	if bm.activeJob != "container-one1" {
		t.Errorf("buildkit activeJob = %q, want %q", bm.activeJob, "container-one1")
	}
}

func TestBuildkitSkipsNonProjectContainers(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, HoneypotConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 0,
		logger:     testBuildkitLogger(),
	}
	mgr.SetBuildkit(bm)

	ctx := context.Background()
	pol := testPolicy("audit")

	// Container without ProjectPath (sibling/helper).
	info := ContainerInfo{ContainerID: "abcdef123456"}
	_, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Buildkit should NOT be attached (no project attribution).
	if bm.activeJob != "" {
		t.Errorf("buildkit should not attach to non-project container, got activeJob = %q", bm.activeJob)
	}
}

// TestBuildkitAttachUsesSharedDNSRecorder is the regression test for the bug
// where BuildkitMonitor.AttachJob was wired with the per-container packet
// recorder (e.recorder) instead of the shared DNS recorder. DNS queries
// captured by the buildkit DNS proxy landed on a recorder that nothing read —
// bucket reports discard the DNS slice from e.recorder.SnapshotAndReset and
// pull DNS activity from nctx.sharedDNSRecorder instead.
//
// The test drives a DNS record through the recorder that AttachJob wired into
// the buildkit monitor (bm.LookupRecorder), then asserts the entry lands on
// the shared DNS recorder, not the per-container packet recorder.
func TestBuildkitAttachUsesSharedDNSRecorder(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, HoneypotConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 0,
		logger:     testBuildkitLogger(),
	}
	mgr.SetBuildkit(bm)

	ctx := context.Background()
	pol := testPolicy("audit")
	info := ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "test/project"}

	e, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if e == nil {
		t.Fatal("attach returned nil enforcer with nil error")
	}

	if bm.LookupRecorder() == nil {
		t.Fatal("buildkit recorder should be set during job")
	}

	// Sanity check: the shared DNS recorder and the per-container packet recorder
	// are distinct objects, so the downstream assertion is meaningful.
	if e.ctx.sharedDNSRecorder == e.recorder {
		t.Fatal("sharedDNSRecorder and e.recorder must be distinct for this test")
	}

	// Simulate a Dockerfile-time DNS query flowing through the buildkit DNS proxy:
	// the proxy resolves bm.LookupRecorder() and calls RecordDNS on it.
	bm.LookupRecorder().RecordDNS("dl-cdn.alpinelinux.org", "A", "dns_allowed",
		[]string{"146.75.30.133"}, 0, "buildkitd", "", "")

	// The entry must be visible on the shared DNS recorder — that's what the
	// bucket reporter reads at enforcer.go:1092.
	_, sharedActivity := e.ctx.sharedDNSRecorder.Snapshot()

	foundShared := false
	for _, entry := range sharedActivity {
		if entry.Domain == "dl-cdn.alpinelinux.org" {
			foundShared = true

			break
		}
	}

	if !foundShared {
		t.Errorf("buildkit DNS query not on sharedDNSRecorder: got %d entries, want entry for %q",
			len(sharedActivity), "dl-cdn.alpinelinux.org")
	}

	// And it must NOT be on the per-container packet recorder — the DNS slice
	// there is dropped by the packet bucket reporter (enforcer.go:1058).
	_, packetActivity := e.recorder.Snapshot()
	for _, entry := range packetActivity {
		if entry.Domain == "dl-cdn.alpinelinux.org" {
			t.Errorf("buildkit DNS query leaked onto per-container packet recorder: %+v", entry)
		}
	}
}

func TestBuildkitLookupRecorderAtomicity(t *testing.T) {
	bm := &BuildkitMonitor{
		cgroupPath: "/sys/fs/cgroup/buildkit",
		cgroupID:   9999,
		drainDelay: 0,
		logger:     testBuildkitLogger(),
	}

	// Initially nil.
	if bm.LookupRecorder() != nil {
		t.Error("expected nil recorder initially")
	}

	// Store a recorder.
	rec := NewViolationRecorder(nil)
	bm.recorder.Store(rec)

	if bm.LookupRecorder() != rec {
		t.Error("expected stored recorder")
	}

	// Clear it.
	bm.recorder.Store(nil)

	if bm.LookupRecorder() != nil {
		t.Error("expected nil after clear")
	}
}
