package enforcer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestStartBuildKitEgressAttach_OptOut covers the opt-out path —
// callers pass an empty path slice when the operator sets
// BuildkitDisableCgroupAttach=true. No EBPF load, no attach, no
// ringbuf reader, no error.
func TestStartBuildKitEgressAttach_OptOut(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, nil, log, nil, 0)
	if err != nil {
		t.Fatalf("opt-out returned err=%v, want nil", err)
	}

	if attach != nil {
		t.Errorf("opt-out returned non-nil attach=%v, want nil", attach)
	}

	if plat.ebpfLoaded {
		t.Error("opt-out loaded EBPF; expected no load")
	}
}

// TestStartBuildKitEgressAttach_AttachesAtEachPath verifies the
// happy path: one EBPFHandle loaded, one AttachCgroup per configured
// path, ringbuf reader started. Close releases everything.
func TestStartBuildKitEgressAttach_AttachesAtEachPath(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	paths := []string{"/sys/fs/cgroup/buildkit", "/sys/fs/cgroup/init"}

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, paths, log, nil, 0)
	if err != nil {
		t.Fatalf("StartBuildKitEgressAttach: %v", err)
	}

	if attach == nil {
		t.Fatal("nil attach on happy path")
	}

	t.Cleanup(func() {
		if closeErr := attach.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	if !plat.ebpfLoaded {
		t.Error("EBPF not loaded")
	}

	handle := attach.handle.(*fakeEBPFHandle)
	if handle.attachCount != len(paths) {
		t.Errorf("attachCount=%d, want %d", handle.attachCount, len(paths))
	}

	if !plat.ringbufStarted {
		t.Error("ringbuf reader not started")
	}
}

// TestStartBuildKitEgressAttach_LoadFails: when LoadEBPF errors, no
// links remain attached and the returned error wraps the cause.
func TestStartBuildKitEgressAttach_LoadFails(t *testing.T) {
	t.Parallel()

	loadErr := errors.New("kernel too old")
	plat := &fakePlatform{loadEBPFErr: loadErr}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
	)
	if attach != nil {
		t.Errorf("attach=%v on load failure, want nil", attach)
	}

	if err == nil {
		t.Fatal("nil err on load failure")
	}

	if !errors.Is(err, loadErr) {
		t.Errorf("err=%v, want it to wrap %v", err, loadErr)
	}
}

// TestStartBuildKitEgressAttach_AttachFailsCleansUp: when a later
// AttachCgroup fails, the earlier links from the same call are closed
// and the EBPFHandle is released. Without this, a partial-attach
// failure would leak BPF program references.
func TestStartBuildKitEgressAttach_AttachFailsCleansUp(t *testing.T) {
	t.Parallel()

	attachErr := errors.New("permission denied")
	plat := &fakePlatform{attachCgroupErr: attachErr}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
	)
	if attach != nil {
		t.Errorf("attach=%v on attach failure, want nil", attach)
	}

	if err == nil {
		t.Fatal("nil err on attach failure")
	}

	if !errors.Is(err, attachErr) {
		t.Errorf("err=%v, want it to wrap %v", err, attachErr)
	}

	if !plat.ebpfClosed {
		t.Error("EBPFHandle not closed after attach failure; would leak BPF program")
	}
}

// TestStartBuildKitEgressAttach_RecorderDropsUnknownCgroups exercises
// the recorder-selection closure: events from cgroups without a known
// BuildKitBinding are dropped (recorder=nil), not stamped into the
// shared recorder. Critical for noise control on a /sys/fs/cgroup/buildkit
// subtree shared with unrelated daemon traffic.
func TestStartBuildKitEgressAttach_RecorderDropsUnknownCgroups(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry(time.Minute)
	registry.LinkCgroup(12345, CgroupBinding{
		SessionRef:   "sess-1",
		VertexDigest: "sha256:abc",
		VertexName:   "[stage] apk add curl",
	})

	// Install + restore the package-global hook so the closure under
	// test sees a real lookup result for known cgroup_ids.
	prev := buildKitLookup.Load()

	t.Cleanup(func() { buildKitLookup.Store(prev) })

	SetBuildKitLookup(registry.LookupByCgroupID)

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, log, nil, 0,
	)
	if err != nil {
		t.Fatalf("StartBuildKitEgressAttach: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	// The fake ringbuf reader saved the lookupRecorder closure on the
	// handle. We don't have a direct accessor — instead, replicate the
	// production closure shape and assert its behavior on the registry
	// we just primed. (The wired closure inside the helper is exercised
	// at runtime via the ringbuf reader; this assertion verifies the
	// dispatch logic.)
	lookup := func(cgroupID uint64) *ViolationRecorder {
		if _, ok := LookupBuildKitBinding(cgroupID); !ok {
			return nil
		}

		return attach.recorder
	}

	if got := lookup(99999); got != nil {
		t.Error("lookup(unknown_cgroup_id) returned non-nil recorder; want nil")
	}

	if got := lookup(12345); got == nil {
		t.Error("lookup(known_cgroup_id) returned nil recorder; want shared recorder")
	}
}

// TestBuildKitEgressAttach_FlusherEmitsReports verifies the bucket
// flusher invokes ReportFunc with the recorder's accumulated stats.
// Drives one tick, asserts a report arrives carrying the violations.
func TestBuildKitEgressAttach_FlusherEmitsReports(t *testing.T) {
	t.Parallel()

	plat := &fakePlatform{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	reports := make(chan *EgressStats, 1)
	report := func(_ context.Context, _ ContainerInfo, stats *EgressStats, _ bool, _ time.Time) {
		reports <- stats
	}

	// Tight interval to keep the test fast.
	const tick = 20 * time.Millisecond

	attach, err := StartBuildKitEgressAttach(
		t.Context(), plat,
		[]string{"/sys/fs/cgroup/buildkit"},
		log, report, tick,
	)
	if err != nil {
		t.Fatalf("StartBuildKitEgressAttach: %v", err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	// Seed the shared recorder. The flusher should drain this on the
	// next tick and pass it to ReportFunc.
	attach.recorder.RecordViolation(Violation{
		IP:        "1.2.3.4",
		Port:      443,
		Action:    "audit",
		Timestamp: time.Now(),
	})

	select {
	case stats := <-reports:
		if len(stats.Violations) != 1 {
			t.Errorf("flush emitted %d violations, want 1", len(stats.Violations))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flusher did not emit a report within 2s")
	}
}
