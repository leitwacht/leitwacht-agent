//go:build linux && integration

package enforcer

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegrationPodCgroupAttach validates the pod-cgroup attach mechanics
// against a real kernel and bpftool, without spinning up containers.
//
// Synthesises a K8s-shaped cgroup hierarchy under /sys/fs/cgroup, parses
// the pod-slice path from the synthesised sandbox path, attaches the
// egress_filter program at the derived pod slice via the real LinuxPlatform,
// and confirms via `bpftool cgroup show` that the program is bound there
// (and removed after Close). Doesn't go through Manager.AttachPodSandbox
// because that flow brings up the DNS proxy + nftables redirect inside the
// target netns — a real ctr-based test for the full path is the natural
// next step but is gated on Layer-2 integration scaffolding being in place.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationPodCgroupAttach -v -count=1
func TestIntegrationPodCgroupAttach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	if _, err := exec.LookPath("bpftool"); err != nil {
		t.Skip("requires bpftool on PATH")
	}

	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("requires cgroupv2 unified hierarchy")
	}

	const podUID = "9e3c2d70_7e1a_4cb4_8ab9_c7a5f1d2e3b4"

	testRoot := "/sys/fs/cgroup/leitwacht-pod-test"
	podSlice := filepath.Join(testRoot, "kubepods-burstable-pod"+podUID+".slice")
	sandboxScope := filepath.Join(podSlice, "cri-containerd-fakesb.scope")

	err := os.MkdirAll(sandboxScope, 0o755)
	if err != nil {
		t.Fatalf("mkdir sandbox scope: %v", err)
	}

	t.Cleanup(func() {
		// cgroupv2 rmdir requires the cgroup to be empty (no procs, no
		// children). We never moved anything into these synthetic
		// cgroups, so bottom-up rmdir succeeds.
		_ = os.Remove(sandboxScope)
		_ = os.Remove(podSlice)
		_ = os.Remove(testRoot)
	})

	// Parser must derive the synthesised pod slice from the sandbox path.
	derivedPod, err := PodCgroupFromContainer(sandboxScope)
	if err != nil {
		t.Fatalf("PodCgroupFromContainer(%q): %v", sandboxScope, err)
	}

	if derivedPod != podSlice {
		t.Fatalf("parser: got %q, want %q", derivedPod, podSlice)
	}

	// Load eBPF and attach at pod slice via the real LinuxPlatform.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	platform := &LinuxPlatform{Logger: log}

	handle, err := platform.LoadEBPF(true, nil)
	if err != nil {
		t.Fatalf("LoadEBPF: %v", err)
	}

	defer func() { _ = handle.Close() }()

	link, err := handle.AttachCgroup(podSlice)
	if err != nil {
		t.Fatalf("AttachCgroup at pod slice %q: %v", podSlice, err)
	}

	// Verify via bpftool that egress_filter is attached at the pod slice.
	preOut, _ := exec.Command("bpftool", "cgroup", "show", podSlice).CombinedOutput()
	t.Logf("bpftool cgroup show %s (after attach):\n%s", podSlice, string(preOut))

	if !strings.Contains(string(preOut), "egress_filter") {
		t.Errorf("expected egress_filter at pod slice; bpftool output:\n%s", string(preOut))
	}

	// Detach and verify the program is no longer attached at the pod slice.
	closeErr := link.Close()
	if closeErr != nil {
		t.Errorf("link close: %v", closeErr)
	}

	postOut, _ := exec.Command("bpftool", "cgroup", "show", podSlice).CombinedOutput()
	t.Logf("bpftool cgroup show %s (after detach):\n%s", podSlice, string(postOut))

	if strings.Contains(string(postOut), "egress_filter") {
		t.Errorf("egress_filter still attached after Close; bpftool output:\n%s", string(postOut))
	}
}
