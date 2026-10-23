package enforcer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const (
	testPodUID         = "9e3c2d70-7e1a-4cb4-8ab9-c7a5f1d2e3b4"
	testPodUIDSystemd  = "9e3c2d70_7e1a_4cb4_8ab9_c7a5f1d2e3b4"
	testSandboxID      = "sandbox123456abcdef"
	testBuildID        = "build123456abcdef"
	testSandboxPID     = 100
	testBuildPID       = 200
	testSharedNetnsIno = 999
)

// makePodCgroupTree builds a K8s systemd-driver cgroup hierarchy under
// t.TempDir() and returns (sandboxCgroup, buildCgroup, podCgroup). All
// three directories exist on disk so os.Stat(podCgroup) succeeds.
func makePodCgroupTree(t *testing.T) (sandbox, build, pod string) {
	t.Helper()

	root := t.TempDir()
	pod = filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod"+testPodUIDSystemd+".slice")
	sandbox = filepath.Join(pod, "cri-containerd-"+testSandboxID+".scope")
	build = filepath.Join(pod, "cri-containerd-"+testBuildID+".scope")

	for _, d := range []string{sandbox, build} {
		err := os.MkdirAll(d, 0o755)
		if err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	return sandbox, build, pod
}

func TestAttachPodSandbox_AttachesAtPodCgroup(t *testing.T) {
	sandboxCgroup, _, _ := makePodCgroupTree(t)

	fp := &fakePlatform{
		// Both sandbox PID and any later container PID resolve to the
		// same netns inode — same pod.
		netnsByPID: map[int]uint64{
			testSandboxPID: testSharedNetnsIno,
			testBuildPID:   testSharedNetnsIno,
		},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID:     testPodUID,
		SandboxID:  testSandboxID,
		PID:        testSandboxPID,
		CgroupPath: sandboxCgroup,
	})
	if err != nil {
		t.Fatalf("AttachPodSandbox: %v", err)
	}

	mgr.mu.Lock()
	nctx, ok := mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	if !ok {
		t.Fatal("NetnsContext was not created for sandbox netns")
	}

	if !nctx.podAttached {
		t.Error("podAttached should be true after AttachPodSandbox")
	}

	if nctx.podCgroupLink == nil {
		t.Error("podCgroupLink should be non-nil after pod attach")
	}

	if nctx.sandboxID != testSandboxID {
		t.Errorf("sandboxID = %q, want %q", nctx.sandboxID, testSandboxID)
	}

	if nctx.podUID != testPodUID {
		t.Errorf("podUID = %q, want %q", nctx.podUID, testPodUID)
	}

	// After pod attach, fakeEBPFHandle.attachCount should be 1 — the pod-cgroup attach.
	handle, _ := nctx.ebpf.(*fakeEBPFHandle)
	if got := handle.attachCount; got != 1 {
		t.Errorf("after pod attach: attachCount = %d, want 1", got)
	}

	// pod-cgroup ID should be registered in cgroupRecorders to route
	// softirq-context fallbacks to the pod-shared DNS recorder.
	nctx.mu.RLock()
	rec, exists := nctx.cgroupRecorders[nctx.podCgroupID]
	nctx.mu.RUnlock()

	if !exists {
		t.Error("pod cgroup ID should map to sharedDNSRecorder in cgroupRecorders")
	}

	if rec != nctx.sharedDNSRecorder {
		t.Error("pod cgroup ID should map to sharedDNSRecorder specifically")
	}

	// Refcount should be 1 (sandbox holds a ref).
	mgr.mu.Lock()
	gotRefcount := nctx.refcount
	mgr.mu.Unlock()

	if gotRefcount != 1 {
		t.Errorf("refcount = %d, want 1 (sandbox)", gotRefcount)
	}
}

// TestAttachPodSandbox_BuildContainerJoinSkipsAttachCgroup: after pod-attach,
// the build container's Attach() must NOT call AttachCgroup again — it joins
// the existing NetnsContext and only registers a recorder.
func TestAttachPodSandbox_BuildContainerJoinSkipsAttachCgroup(t *testing.T) {
	sandboxCgroup, buildCgroup, _ := makePodCgroupTree(t)

	fp := &fakePlatform{
		netnsByPID: map[int]uint64{
			testSandboxPID: testSharedNetnsIno,
			testBuildPID:   testSharedNetnsIno,
		},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID: testPodUID, SandboxID: testSandboxID,
		PID: testSandboxPID, CgroupPath: sandboxCgroup,
	})
	if err != nil {
		t.Fatalf("AttachPodSandbox: %v", err)
	}

	mgr.mu.Lock()
	nctx := mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	handle := nctx.ebpf.(*fakeEBPFHandle)
	beforeAttachCount := handle.attachCount

	// Real build container joins the same pod.
	info := ContainerInfo{
		ContainerID: testBuildID,
		ProjectPath: "test/project",
		CgroupPath:  buildCgroup,
	}

	_, err = mgr.Attach(context.Background(), info, testBuildPID, testPolicy("audit"))
	if err != nil {
		t.Fatalf("Attach build container: %v", err)
	}

	if got := handle.attachCount; got != beforeAttachCount {
		t.Errorf("build container caused %d additional AttachCgroup calls; want 0 (pod-attached)",
			got-beforeAttachCount)
	}
}

// TestAttachPodSandbox_FallbackOnNonK8sPath: Docker-shaped sandbox cgroup
// returns nil without creating any pod attach state — falls through to the
// per-container path that fires when the build container later starts.
func TestAttachPodSandbox_FallbackOnNonK8sPath(t *testing.T) {
	fp := &fakePlatform{
		netnsByPID: map[int]uint64{testSandboxPID: testSharedNetnsIno},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID:     testPodUID,
		SandboxID:  testSandboxID,
		PID:        testSandboxPID,
		CgroupPath: "/sys/fs/cgroup/docker/abc123def456",
	})
	if err != nil {
		t.Fatalf("AttachPodSandbox should not error on fallback: %v", err)
	}

	// No nctx should be created — the fallback is silent. The per-container
	// attach in HandleStart→Attach will create the nctx later.
	mgr.mu.Lock()
	_, exists := mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	if exists {
		t.Error("non-K8s sandbox path should not create a NetnsContext")
	}
}

// TestAttachPodSandbox_StatMissingFalls Back: even when path looks K8s-shaped,
// missing pod cgroup directory triggers fallback (concurrent pod teardown).
func TestAttachPodSandbox_StatMissingFallsBack(t *testing.T) {
	fp := &fakePlatform{
		netnsByPID: map[int]uint64{testSandboxPID: testSharedNetnsIno},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	// K8s-shape path that doesn't exist on disk.
	bogusPath := "/nonexistent/kubepods.slice/kubepods-burstable.slice/" +
		"kubepods-burstable-pod" + testPodUIDSystemd + ".slice/cri-containerd-x.scope"

	err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID:     testPodUID,
		SandboxID:  testSandboxID,
		PID:        testSandboxPID,
		CgroupPath: bogusPath,
	})
	if err != nil {
		t.Fatalf("AttachPodSandbox should not error when stat fails: %v", err)
	}

	mgr.mu.Lock()
	_, exists := mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	if exists {
		t.Error("missing pod cgroup directory should not create a NetnsContext")
	}
}

// TestDetachPodSandbox_TriggersTeardown: with NetnsGrace=0 and no other
// containers attached, DetachPodSandbox triggers immediate teardown.
func TestDetachPodSandbox_TriggersTeardown(t *testing.T) {
	sandboxCgroup, _, _ := makePodCgroupTree(t)

	fp := &fakePlatform{
		netnsByPID: map[int]uint64{testSandboxPID: testSharedNetnsIno},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0 // immediate teardown
	defer mgr.DetachAll()

	err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID: testPodUID, SandboxID: testSandboxID,
		PID: testSandboxPID, CgroupPath: sandboxCgroup,
	})
	if err != nil {
		t.Fatalf("AttachPodSandbox: %v", err)
	}

	mgr.DetachPodSandbox(testPodUID, testSandboxID)

	if !fp.ebpfClosed {
		t.Error("eBPF handle should be closed after sandbox teardown")
	}

	if !fp.redirectRemoved {
		t.Error("DNS redirect should be removed after sandbox teardown")
	}

	mgr.mu.Lock()
	_, exists := mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	if exists {
		t.Error("NetnsContext should be removed from the map after teardown")
	}
}

// TestAttachPodSandbox_SandboxChangedDoesNotLeakRefcount: kubelet can
// replace a pod's sandbox; the replaced sandbox's reference must be
// released before re-attaching, otherwise every replacement leaks one
// and the netns context never reaches refcount 0 (never torn down).
func TestAttachPodSandbox_SandboxChangedDoesNotLeakRefcount(t *testing.T) {
	sandboxCgroup, _, _ := makePodCgroupTree(t)

	fp := &fakePlatform{
		netnsByPID: map[int]uint64{testSandboxPID: testSharedNetnsIno},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	attach := func(sandboxID string) {
		t.Helper()

		err := mgr.AttachPodSandbox(PodSandboxInfo{
			PodUID: testPodUID, SandboxID: sandboxID,
			PID: testSandboxPID, CgroupPath: sandboxCgroup,
		})
		if err != nil {
			t.Fatalf("AttachPodSandbox(%s): %v", sandboxID, err)
		}
	}

	attach(testSandboxID)
	attach("replacement-sandbox-0001")
	attach("replacement-sandbox-0002")

	mgr.mu.Lock()
	nctx := mgr.netnsContexts[testSharedNetnsIno]
	refs, sandbox := nctx.refcount, nctx.sandboxID
	mgr.mu.Unlock()

	if refs != 1 {
		t.Fatalf("refcount after two SandboxChanged = %d, want 1", refs)
	}

	if sandbox != "replacement-sandbox-0002" {
		t.Fatalf("sandboxID = %q, want the latest replacement", sandbox)
	}

	// The replaced sandboxes' late die events are no-ops; only the live one tears down.
	mgr.DetachPodSandbox(testPodUID, testSandboxID)

	mgr.mu.Lock()
	_, stillThere := mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	if !stillThere {
		t.Fatal("die event for a replaced sandbox tore down the live context")
	}

	mgr.DetachPodSandbox(testPodUID, "replacement-sandbox-0002")

	mgr.mu.Lock()
	_, stillThere = mgr.netnsContexts[testSharedNetnsIno]
	mgr.mu.Unlock()

	if stillThere {
		t.Fatal("context leaked after the live sandbox died (refcount leak)")
	}
}

// TestPodSandbox_ConcurrentEventsRace drives sandbox replacement,
// sandbox die, and real-container attach concurrently. Meaningful under
// -race: sandboxID / podAttached used to be written under nctx.mu but
// read under Manager.mu.
func TestPodSandbox_ConcurrentEventsRace(t *testing.T) {
	sandboxCgroup, _, _ := makePodCgroupTree(t)

	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{testSandboxPID: testSharedNetnsIno, testBuildPID: testSharedNetnsIno},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	if err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID: testPodUID, SandboxID: testSandboxID, PID: testSandboxPID, CgroupPath: sandboxCgroup,
	}); err != nil {
		t.Fatalf("AttachPodSandbox: %v", err)
	}

	var wg sync.WaitGroup

	// Sandbox replacement loop (writes sandboxID / podAttached / refcount).
	wg.Go(func() {
		for i := range 40 {
			_ = mgr.AttachPodSandbox(PodSandboxInfo{
				PodUID: testPodUID, SandboxID: fmt.Sprintf("sandbox-%02d-abcdef", i),
				PID: testSandboxPID, CgroupPath: sandboxCgroup,
			})
		}
	})

	// Real-container attach/detach loop (reads podAttached in attachEnforcer).
	wg.Go(func() {
		for i := range 40 {
			cid := fmt.Sprintf("build-%02d-abcdefgh", i)
			_, _ = mgr.Attach(context.Background(), ContainerInfo{ContainerID: cid}, testBuildPID, testPolicy("audit"))
			mgr.Detach(cid)
		}
	})

	wg.Wait()
}

func podGateManager(t *testing.T) (*Manager, string) {
	t.Helper()

	sandboxCgroup, _, _ := makePodCgroupTree(t)

	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			testSandboxPID: testSharedNetnsIno, testBuildPID: testSharedNetnsIno, 300: testSharedNetnsIno,
		},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	t.Cleanup(func() { mgr.DetachAll() })

	return mgr, sandboxCgroup
}

func gateOpen(t *testing.T, mgr *Manager) bool {
	t.Helper()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	return mgr.netnsContexts[testSharedNetnsIno].egressAttached.Load()
}

// TestAttachedSignalRealPodOrdering models the real runner pod order:
// sandbox start, then the init container (no job env, so only a sibling
// PrepareNetns), and only after initc exits the build container's Attach.
// The gate must open before any container Attach (otherwise initc, which
// blocks the build container from starting, would time out), and the later
// build Attach must reconcile the netns to block.
func TestAttachedSignalRealPodOrdering(t *testing.T) {
	mgr, sandboxCgroup := podGateManager(t)

	if err := mgr.AttachPodSandbox(PodSandboxInfo{
		PodUID: testPodUID, SandboxID: testSandboxID, PID: testSandboxPID, CgroupPath: sandboxCgroup,
	}); err != nil {
		t.Fatalf("AttachPodSandbox: %v", err)
	}

	if !gateOpen(t, mgr) {
		t.Fatal("pod-level attach did not arm the attached signal; initc would deadlock the pod")
	}

	if err := mgr.PrepareNetns("initc0000000000", 300, "/sys/fs/cgroup/initc"); err != nil {
		t.Fatalf("PrepareNetns: %v", err)
	}

	if !gateOpen(t, mgr) {
		t.Fatal("gate closed after the initc sibling started")
	}

	mgr.mu.Lock()
	audit := mgr.netnsContexts[testSharedNetnsIno].auditMode.Load()
	mgr.mu.Unlock()

	if !audit {
		t.Fatal("netns should still be the audit-all placeholder before the build container attaches")
	}

	if _, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "build0000000", ProjectPath: "team/app"},
		testBuildPID, testPolicy("block")); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	mgr.mu.Lock()
	audit = mgr.netnsContexts[testSharedNetnsIno].auditMode.Load()
	mgr.mu.Unlock()

	if audit {
		t.Fatal("build container's Attach did not reconcile the netns to block mode")
	}
}

// Without a pod link (Docker-style / fallback) a sibling's attach arms the
// signal.
func TestAttachedSignalSiblingWithoutPodLink(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test", netnsByPID: map[int]uint64{300: testSharedNetnsIno}}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	defer mgr.DetachAll()

	if err := mgr.PrepareNetns("helper0000000000", 300, "/sys/fs/cgroup/helper"); err != nil {
		t.Fatalf("PrepareNetns: %v", err)
	}

	if !gateOpen(t, mgr) {
		t.Fatal("sibling on a non-pod netns did not arm the attached signal")
	}
}
