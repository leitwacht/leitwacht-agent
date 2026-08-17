package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// fakePlatform implements Platform for unit testing orchestration logic.
type fakePlatform struct {
	cgroupPath       string
	cgroupErr        error
	bindErr          error
	setupRedirectErr error
	loadEBPFErr      error
	netnsErr         error
	attachCgroupErr  error
	// netnsByPID maps pid → netns inode. Tests use this to simulate
	// pod-shared network namespaces. Pids missing from the map fall back
	// to inode = uint64(pid), so each pid is its own netns by default.
	netnsByPID map[int]uint64

	boundAddr       string
	redirectSetup   bool
	redirectRemoved bool
	ebpfLoaded      bool
	ebpfClosed      bool
	ringbufStarted  bool
	allowedIPs      []string
	allowedHosts    []string
	deniedIPs       []string
	loadCount       int
	cgroupIDCounter atomic.Uint64

	// ipPrio records the priority each {ip, port} entry was installed
	// with, keyed the same way as the allowedHosts / deniedIPs slices.
	// Kept out of those slices so the ordering assertions can stay
	// written in terms of plain "ip:port" strings.
	ipPrio map[string]uint32
}

func (f *fakePlatform) recordPrio(entry string, prio uint32) {
	if f.ipPrio == nil {
		f.ipPrio = make(map[string]uint32)
	}

	f.ipPrio[entry] = prio
}

func (f *fakePlatform) GetCgroupPath(_ int) (string, error) {
	return f.cgroupPath, f.cgroupErr
}

func (f *fakePlatform) NetnsInode(pid int) (uint64, error) {
	if f.netnsErr != nil {
		return 0, f.netnsErr
	}

	if ino, ok := f.netnsByPID[pid]; ok {
		return ino, nil
	}

	return uint64(pid), nil
}

func (f *fakePlatform) BindInNetns(_ int, addr string) (net.PacketConn, net.Listener, error) {
	if f.bindErr != nil {
		return nil, nil, f.bindErr
	}
	f.boundAddr = addr
	udp, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	tcp, _ := net.Listen("tcp4", "127.0.0.1:0")
	return udp, tcp, nil
}

func (f *fakePlatform) SetupDNSRedirect(_ int) error {
	if f.setupRedirectErr != nil {
		return f.setupRedirectErr
	}
	f.redirectSetup = true
	return nil
}

func (f *fakePlatform) RemoveDNSRedirect(_ int) error {
	f.redirectRemoved = true
	return nil
}

func (f *fakePlatform) LoadEBPF(_ bool, _ []net.IPNet) (EBPFHandle, error) {
	if f.loadEBPFErr != nil {
		return nil, f.loadEBPFErr
	}
	f.ebpfLoaded = true
	f.loadCount++
	return &fakeEBPFHandle{platform: f}, nil
}

func (f *fakePlatform) CgroupID(_ string) (uint64, error) {
	return f.cgroupIDCounter.Add(1), nil
}

func (f *fakePlatform) DialUpstreamInNetns(_ int, _ string, _ int) (*net.UDPConn, error) {
	return nil, nil //nolint:nilnil // fake: Docker upstream not needed in unit tests
}

// fakeEBPFHandle tracks calls for verification.
type fakeEBPFHandle struct {
	platform    *fakePlatform
	attachCount int
	auditMode   bool // last mode set via SetMode
	modeUpdated bool // true after SetMode is called
	// ringbufAuditSrc is the live audit-mode cell captured by
	// StartRingbufReader. Tests use this to assert the reader observes the
	// post-flip mode rather than a value snapshotted at start.
	ringbufAuditSrc *atomic.Bool
}

func (h *fakeEBPFHandle) AddAllowedIP(ip net.IP, ports []int, _ uint32) error {
	h.platform.allowedIPs = append(h.platform.allowedIPs, ip.String())
	return nil
}

func (h *fakeEBPFHandle) AddAllowedHost(ip net.IP, port int, prio uint32) error {
	entry := fmt.Sprintf("%s:%d", ip, port)
	h.platform.allowedHosts = append(h.platform.allowedHosts, entry)
	h.platform.recordPrio(entry, prio)
	return nil
}

func (h *fakeEBPFHandle) RemoveAllowedHost(ip net.IP, port int) error {
	h.platform.allowedHosts = removeEntry(h.platform.allowedHosts, fmt.Sprintf("%s:%d", ip, port))
	return nil
}

func (h *fakeEBPFHandle) AddDeniedIP(ip net.IP, port int, prio uint32) error {
	entry := fmt.Sprintf("%s:%d", ip, port)
	h.platform.deniedIPs = append(h.platform.deniedIPs, entry)
	h.platform.recordPrio(entry, prio)
	return nil
}

func (h *fakeEBPFHandle) RemoveDeniedIP(ip net.IP, port int) error {
	h.platform.deniedIPs = removeEntry(h.platform.deniedIPs, fmt.Sprintf("%s:%d", ip, port))
	return nil
}

// removeEntry drops every occurrence of target, in place.
func removeEntry(entries []string, target string) []string {
	out := entries[:0]
	for _, e := range entries {
		if e != target {
			out = append(out, e)
		}
	}
	return out
}

func (h *fakeEBPFHandle) ReadStats() int64 { return 42 }

func (h *fakeEBPFHandle) StartRingbufReader(
	_ context.Context,
	_ func(uint64) *ViolationRecorder,
	auditMode *atomic.Bool,
) (func(), error) {
	h.platform.ringbufStarted = true
	h.ringbufAuditSrc = auditMode
	return func() {}, nil
}

func (h *fakeEBPFHandle) AttachCgroup(_ string) (CgroupLink, error) {
	if h.platform.attachCgroupErr != nil {
		return nil, h.platform.attachCgroupErr
	}
	h.attachCount++
	return &fakeCgroupLink{}, nil
}

func (h *fakeEBPFHandle) SetMode(audit bool) error {
	h.auditMode = audit
	h.modeUpdated = true

	return nil
}

func (h *fakeEBPFHandle) Close() error {
	h.platform.ebpfClosed = true
	return nil
}

func (h *fakeEBPFHandle) AddSockKnownCgroup(_ uint64) error { return nil }
func (h *fakeEBPFHandle) RemoveSockKnownCgroup(_ uint64)    {}

// fakeCgroupLink tracks cgroup link closes.
type fakeCgroupLink struct {
	closed bool
}

func (l *fakeCgroupLink) Close() error {
	l.closed = true
	return nil
}

func testPolicy(action string) *policy.ResolvedPolicy {
	p := &policy.ResolvedPolicy{
		ProjectPath: "test/project",
		Action:      action,
		RuleSets: map[string][]policy.Rule{
			"": {{
				Pattern:     "example.com",
				PatternType: policy.PatternFQDN,
				Action:      policy.ActionAllow,
				Ports:       []int{443},
			}},
		},
	}
	p.BuildLookups()
	return p
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestContainerScopeCgroup(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "docker systemd driver strips /init",
			in:   "/sys/fs/cgroup/system.slice/docker-abc.scope/init",
			want: "/sys/fs/cgroup/system.slice/docker-abc.scope",
		},
		{
			name: "containerd leaf is unchanged",
			in:   "/sys/fs/cgroup/system.slice/containerd.service/kubepods/pod-x/container-y",
			want: "/sys/fs/cgroup/system.slice/containerd.service/kubepods/pod-x/container-y",
		},
		{
			name: "k8s leaf is unchanged",
			in:   "/sys/fs/cgroup/kubepods/besteffort/pod-x/container-y",
			want: "/sys/fs/cgroup/kubepods/besteffort/pod-x/container-y",
		},
		{
			name: "root /init is preserved (no walk-up to empty)",
			in:   "/init",
			want: "/init",
		},
		{
			name: "init in middle of path is unaffected",
			in:   "/sys/fs/cgroup/init.scope/foo",
			want: "/sys/fs/cgroup/init.scope/foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := containerScopeCgroup(tc.in)
			if got != tc.want {
				t.Errorf("containerScopeCgroup(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAttachDetachHappyPath(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0 // immediate teardown for this test
	defer mgr.DetachAll()
	ctx := context.Background()

	info := ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "test/project"}
	pol := testPolicy("audit")

	e, err := mgr.Attach(ctx, info, 1234, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil enforcer")
	}

	if !fp.redirectSetup {
		t.Error("nftables redirect not set up")
	}
	if !fp.ebpfLoaded {
		t.Error("eBPF not loaded")
	}
	if !fp.ringbufStarted {
		t.Error("ringbuf reader not started")
	}
	if !mgr.IsEnforced("abcdef123456") {
		t.Error("container should be enforced")
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1", mgr.Count())
	}

	// Detach
	result := mgr.Detach("abcdef123456")
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}
	if result.Stats.TotalBytesSent != 42 {
		t.Errorf("bytes = %d, want 42", result.Stats.TotalBytesSent)
	}
	if !fp.ebpfClosed {
		t.Error("eBPF not closed")
	}
	if !fp.redirectRemoved {
		t.Error("nftables redirect not removed")
	}
	if mgr.IsEnforced("abcdef123456") {
		t.Error("container should not be enforced after detach")
	}
}

func TestAttachSkipsAllowAction(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	pol := testPolicy("allow")
	e, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e != nil {
		t.Error("expected nil enforcer for allow action")
	}
	if fp.ebpfLoaded {
		t.Error("eBPF should not be loaded for allow action")
	}
}

func TestAttachMaxConcurrency(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 1, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()

	// First attach succeeds.
	pol := testPolicy("audit")
	_, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "container-one1"}, 1, pol)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}

	// Second attach skipped (max concurrency = 1).
	e, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "container-two2"}, 2, pol)
	if err != nil {
		t.Fatalf("second attach should not error: %v", err)
	}
	if e != nil {
		t.Error("second attach should return nil (max concurrency)")
	}
}

func TestAttachDuplicateContainerSkipped(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()

	pol := testPolicy("audit")
	info := ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "test/project"}

	// First attach succeeds.
	_, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}

	// Second attach with same containerID is skipped (no leak).
	e, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("duplicate should not error: %v", err)
	}
	if e != nil {
		t.Error("duplicate should return nil")
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1 (not 2)", mgr.Count())
	}
}

func TestAttachSiblingJoinsNetnsContext(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 4242,
			101: 4242,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	// First container in the pod attaches normally.
	primary, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 100, pol)
	if err != nil {
		t.Fatalf("primary attach: %v", err)
	}
	if primary == nil {
		t.Fatal("primary should attach")
	}

	// Sibling container in the same pod joins the existing NetnsContext.
	sib, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "sibling00001"}, 101, pol)
	if err != nil {
		t.Fatalf("sibling attach: %v", err)
	}
	if sib == nil {
		t.Fatal("sibling should attach (joins shared context)")
	}

	if mgr.Count() != 2 {
		t.Errorf("count = %d, want 2 (both siblings enforced)", mgr.Count())
	}

	// LoadEBPF should be called only once (shared).
	if fp.loadCount != 1 {
		t.Errorf("loadCount = %d, want 1 (shared eBPF)", fp.loadCount)
	}

	// Both should share the same NetnsContext.
	if primary.ctx != sib.ctx {
		t.Error("siblings should share the same NetnsContext")
	}
}

func TestDetachSiblingRefcountDecrement(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 4242,
			101: 4242,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0 // immediate teardown for this test
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	_, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 100, pol)
	if err != nil {
		t.Fatalf("primary attach: %v", err)
	}

	_, err = mgr.Attach(ctx, ContainerInfo{ContainerID: "sibling00001"}, 101, pol)
	if err != nil {
		t.Fatalf("sibling attach: %v", err)
	}

	// Detach sibling — eBPF should NOT be closed (primary still active).
	fp.ebpfClosed = false
	mgr.Detach("sibling00001")
	if fp.ebpfClosed {
		t.Error("eBPF should not be closed while primary is still active")
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1", mgr.Count())
	}

	// Detach primary — eBPF should be closed (last in pod).
	mgr.Detach("primary00000")
	if !fp.ebpfClosed {
		t.Error("eBPF should be closed after last container detaches")
	}
	if mgr.Count() != 0 {
		t.Errorf("count = %d, want 0", mgr.Count())
	}
}

func TestDetachPrimaryUpdatesLivePID(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 4242,
			101: 4242,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	primary, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 100, pol)
	if err != nil {
		t.Fatalf("primary attach: %v", err)
	}
	if primary == nil {
		t.Fatal("primary attach returned nil enforcer")
	}

	_, err = mgr.Attach(ctx, ContainerInfo{ContainerID: "sibling00001"}, 101, pol)
	if err != nil {
		t.Fatalf("sibling attach: %v", err)
	}

	nctx := primary.ctx
	if nctx.primaryPID != 100 {
		t.Fatalf("initial primaryPID = %d, want 100", nctx.primaryPID)
	}

	// Detach primary — primaryPID should update to the surviving sibling.
	mgr.Detach("primary00000")
	if nctx.primaryPID != 101 {
		t.Errorf("primaryPID after primary detach = %d, want 101", nctx.primaryPID)
	}
}

func TestSiblingAttachFailureNoRefcountLeak(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 4242,
			101: 4242,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	primary, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 100, pol)
	if err != nil {
		t.Fatalf("primary attach: %v", err)
	}
	if primary == nil {
		t.Fatal("primary should attach")
	}

	// Make sibling's cgroup attachment fail.
	fp.attachCgroupErr = errors.New("cgroup attach failed")
	_, err = mgr.Attach(ctx, ContainerInfo{ContainerID: "sibling00001"}, 101, pol)
	if err == nil {
		t.Fatal("sibling attach should fail")
	}

	// Primary should still be enforced, context intact.
	if !mgr.IsEnforced("primary00000") {
		t.Error("primary should still be enforced")
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1", mgr.Count())
	}

	// Detach primary should still work cleanly.
	result := mgr.Detach("primary00000")
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}
}

func TestRecorderRoutingPerContainer(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 4242,
			101: 4242,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	e1, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 100, pol)
	if err != nil {
		t.Fatalf("primary attach: %v", err)
	}
	if e1 == nil {
		t.Fatal("e1 attach returned nil enforcer")
	}

	e2, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "sibling00001"}, 101, pol)
	if err != nil {
		t.Fatalf("sibling attach: %v", err)
	}
	if e2 == nil {
		t.Fatal("e2 attach returned nil enforcer")
	}

	// Record violations on each enforcer's recorder (packet-level only).
	e1.recorder.RecordViolation(Violation{IP: "1.2.3.4", Port: 80, Action: "packet_dropped"})
	e2.recorder.RecordViolation(Violation{IP: "5.6.7.8", Port: 443, Action: "packet_dropped"})

	// Snapshot each — should only see own violations.
	v1, _ := e1.recorder.Snapshot()
	v2, _ := e2.recorder.Snapshot()

	if len(v1) != 1 || v1[0].IP != "1.2.3.4" {
		t.Errorf("e1 violations = %+v, want [1.2.3.4]", v1)
	}
	if len(v2) != 1 || v2[0].IP != "5.6.7.8" {
		t.Errorf("e2 violations = %+v, want [5.6.7.8]", v2)
	}
}

func TestAttachDistinctNetnsBothEnforced(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			200: 1111,
			201: 2222,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	_, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "container0001"}, 200, pol)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}

	e2, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "container0002"}, 201, pol)
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}

	if e2 == nil {
		t.Error("container in distinct netns should attach")
	}

	if mgr.Count() != 2 {
		t.Errorf("count = %d, want 2", mgr.Count())
	}

	// Different netns = different LoadEBPF calls.
	if fp.loadCount != 2 {
		t.Errorf("loadCount = %d, want 2", fp.loadCount)
	}
}

func TestAttachAfterPrimaryDetachedReusesNetns(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			300: 9999,
			301: 9999,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	_, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 300, pol)
	if err != nil {
		t.Fatalf("primary attach: %v", err)
	}

	// Detach the primary; the netns context should be torn down (refcount 0).
	mgr.Detach("primary00000")

	// A new container in the same netns can now attach as a new creator.
	e, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "successor001"}, 301, pol)
	if err != nil {
		t.Fatalf("successor attach: %v", err)
	}

	if e == nil {
		t.Error("successor in released netns should attach")
	}

	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1", mgr.Count())
	}
}

func TestAttachFailureReleasesNetnsOwner(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath:  "/sys/fs/cgroup/test",
		loadEBPFErr: errors.New("ebpf failed"),
		netnsByPID: map[int]uint64{
			400: 7777,
			401: 7777,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	pol := testPolicy("audit")

	// First attach fails partway through; the netns context reservation must
	// be rolled back so a sibling can still claim the netns.
	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "failed0000001"}, 400, pol)
	if err == nil {
		t.Fatal("expected ebpf failure")
	}

	fp.loadEBPFErr = nil

	e, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "retry00000001"}, 401, pol)
	if err != nil {
		t.Fatalf("retry attach: %v", err)
	}

	if e == nil {
		t.Error("retry in same netns after failure should attach")
	}
}

func TestAttachFailureCleansSentinel(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath:  "/sys/fs/cgroup/test",
		loadEBPFErr: errors.New("ebpf failed"),
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	pol := testPolicy("audit")
	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err == nil {
		t.Fatal("expected error")
	}

	// Sentinel slot should have been cleaned up.
	if mgr.Count() != 0 {
		t.Errorf("count = %d after failed attach, want 0", mgr.Count())
	}

	// Should be able to re-attach after failure.
	fp.loadEBPFErr = nil
	_, err = mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err != nil {
		t.Fatalf("re-attach after failure: %v", err)
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d after re-attach, want 1", mgr.Count())
	}
}

func TestAttachRollbackOnNftablesFailure(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath:       "/sys/fs/cgroup/test",
		setupRedirectErr: errors.New("nftables failed"),
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	pol := testPolicy("block")
	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err == nil {
		t.Fatal("expected error from nftables failure")
	}

	if mgr.IsEnforced("abcdef123456") {
		t.Error("container should not be enforced after failure")
	}
}

func TestAttachRollbackOnEBPFFailure(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath:  "/sys/fs/cgroup/test",
		loadEBPFErr: errors.New("ebpf load failed"),
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	pol := testPolicy("audit")
	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err == nil {
		t.Fatal("expected error from eBPF failure")
	}

	if mgr.IsEnforced("abcdef123456") {
		t.Error("container should not be enforced after failure")
	}
}

func TestAttachRollbackOnCgroupFailure(t *testing.T) {
	fp := &fakePlatform{
		cgroupErr: errors.New("cgroup not found"),
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	pol := testPolicy("audit")
	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err == nil {
		t.Fatal("expected error from cgroup failure")
	}

	if mgr.IsEnforced("abcdef123456") {
		t.Error("container should not be enforced after failure")
	}
}

func TestAttachRollbackOnBindFailure(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		bindErr:    errors.New("bind failed"),
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	pol := testPolicy("block")
	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456"}, 1, pol)
	if err == nil {
		t.Fatal("expected error from bind failure")
	}
	if fp.redirectSetup {
		t.Error("nftables should not be set up after bind failure")
	}
}

func TestDetachNonExistent(t *testing.T) {
	fp := &fakePlatform{}
	mgr := NewManager(testLogger(), 32, nil, nil, fp, CredwatchConfig{}, ProcMemConfig{})

	result := mgr.Detach("nonexistent1234")
	if result != nil {
		t.Error("expected nil result for non-existent container")
	}
}

func TestRecorderRegisteredBeforeReady(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 5555,
			101: 5555,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()
	pol := testPolicy("audit")

	// Attach creator — its recorder must be in cgroupRecorders immediately.
	e, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "primary00000"}, 100, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if e == nil {
		t.Fatal("attach returned nil enforcer")
	}

	// Verify the lookupPacketRecorder callback (used by ringbuf) returns
	// a non-nil recorder for this container's cgroupID. If nil, eBPF packet
	// drop events would be silently discarded.
	nctx := e.ctx
	recorder := nctx.lookupPacketRecorder(e.cgroupID)
	if recorder == nil {
		t.Fatal("lookupPacketRecorder returned nil for creator's cgroupID — packet recording would be broken")
	}
	if recorder != e.recorder {
		t.Fatal("lookupPacketRecorder returned wrong recorder")
	}

	// Verify the shared DNS recorder exists (used by DNS proxy).
	dnsRec := nctx.lookupDNSRecorder(0)
	if dnsRec == nil {
		t.Fatal("lookupDNSRecorder returned nil — DNS recording would be broken")
	}
	if dnsRec != nctx.sharedDNSRecorder {
		t.Fatal("lookupDNSRecorder returned wrong recorder")
	}

	// Same check for a joiner sibling.
	sib, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "sibling00001"}, 101, pol)
	if err != nil {
		t.Fatalf("sibling attach: %v", err)
	}
	if sib == nil {
		t.Fatal("sibling attach returned nil enforcer")
	}

	sibRecorder := nctx.lookupPacketRecorder(sib.cgroupID)
	if sibRecorder == nil {
		t.Fatal("lookupPacketRecorder returned nil for sibling's cgroupID")
	}
	if sibRecorder != sib.recorder {
		t.Fatal("lookupPacketRecorder returned wrong recorder for sibling")
	}
}

func TestDetachCollectsViolations(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	ctx := context.Background()

	info := ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "test/project"}
	pol := testPolicy("block")

	e, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil enforcer")
	}

	// Simulate violations: packet violations go to per-cgroup recorder,
	// DNS activity goes to the shared DNS recorder (no dns_ violations).
	e.recorder.RecordViolation(Violation{IP: "1.2.3.4", Port: 80, Action: "packet_dropped"})
	e.ctx.sharedDNSRecorder.RecordDNS("evil.com", "A", "dns_blocked", nil, 0, "", "", "")
	e.ctx.sharedDNSRecorder.RecordDNS("good.com", "A", "dns_allowed", []string{"5.6.7.8"}, 0, "", "", "")

	result := mgr.Detach("abcdef123456")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Stats.Violations) != 1 {
		t.Errorf("violations = %d, want 1 (packet_dropped only)", len(result.Stats.Violations))
	}
	if len(result.Stats.DNSActivity) != 2 {
		t.Errorf("dns activity = %d, want 2", len(result.Stats.DNSActivity))
	}
	if result.Info.ProjectPath != "test/project" {
		t.Errorf("project = %q, want test/project", result.Info.ProjectPath)
	}
}

// TestDNSBucketReporterIncludesActivity verifies that the periodic DNS flush
// goroutine sends dns_blocked activity in interim reports.
// Regression: DNS activity was discarded on each tick, so blocked
// domains never reached the DB and showed as PASS in the egress view.
func TestDNSBucketReporterIncludesActivity(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	// Enable bucketing with a short interval so the tick fires during the test.
	mgr.BucketInterval = 50 * time.Millisecond

	var reports []EgressStats

	mgr.ReportFunc = func(_ context.Context, _ ContainerInfo, stats *EgressStats, interim bool, _ time.Time) {
		if interim {
			reports = append(reports, *stats)
		}
	}

	ctx := context.Background()
	info := ContainerInfo{ContainerID: "bucket-test0000", ProjectPath: "test/bucket"}
	pol := testPolicy("block")

	e, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if e == nil {
		t.Fatal("attach returned nil enforcer")
	}

	// Simulate a blocked DNS query: only activity on the shared recorder.
	e.ctx.sharedDNSRecorder.RecordDNS("evil.com", "A", "dns_blocked", nil, 0, "nslookup", "bash", "")

	// Wait for at least one bucket tick to fire.
	time.Sleep(150 * time.Millisecond)

	mgr.Detach("bucket-test0000")

	// At least one interim report should have been sent with the DNS activity.
	var foundActivity bool

	for _, r := range reports {
		for _, a := range r.DNSActivity {
			if a.Domain == "evil.com" && a.Action == "dns_blocked" {
				foundActivity = true
			}
		}
	}

	if !foundActivity {
		t.Fatal("DNS bucket reporter must include dns_blocked activity in interim reports; activity was lost")
	}
}

// TestDetachWithGracePeriodCapturesDNS verifies that when the last container
// exits with NetnsGrace > 0, the final report still includes DNS data.
// Regression: the DNS flush goroutine kept running during grace-deferred
// detach, and its SnapshotAndReset could clear the recorder before Detach
// read it — producing empty reports for short-lived containers.
func TestDetachWithGracePeriodCapturesDNS(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 50 * time.Millisecond // short grace so deferred teardown completes quickly
	mgr.BucketInterval = 50 * time.Millisecond

	mgr.ReportFunc = func(_ context.Context, _ ContainerInfo, _ *EgressStats, _ bool, _ time.Time) {}

	ctx := context.Background()

	info := ContainerInfo{ContainerID: "grace-test00000", ProjectPath: "test/grace"}
	pol := testPolicy("block")

	e, err := mgr.Attach(ctx, info, 1, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if e == nil {
		t.Fatal("attach returned nil enforcer")
	}

	// Simulate blocked DNS queries (DNS events are activity only, no violations).
	e.ctx.sharedDNSRecorder.RecordDNS("evil.com", "A", "dns_blocked", nil, 0, "curl", "bash", "")
	e.ctx.sharedDNSRecorder.RecordDNS("allowed.com", "A", "dns_allowed", []string{"1.2.3.4"}, 0, "curl", "bash", "")

	// Detach immediately (simulates a short-lived container).
	result := mgr.Detach("grace-test00000")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Stats.Violations) != 0 {
		t.Fatalf("violations = %d, want 0 (DNS events are activity only)", len(result.Stats.Violations))
	}

	if len(result.Stats.DNSActivity) != 2 {
		t.Fatalf("dns activity = %d, want 2", len(result.Stats.DNSActivity))
	}

	// Wait for deferred teardown to complete so goleak is happy.
	time.Sleep(100 * time.Millisecond)
}

func TestPrepareNetns_SiblingThenBuild(t *testing.T) {
	// Both containers share the same pod netns (inode 9999).
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 9999, 101: 9999},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()
	ctx := context.Background()

	// Step 1: Helper container starts — PrepareNetns sets up DNS infra.
	err := mgr.PrepareNetns("helper0000000000", 100, "/sys/fs/cgroup/helper")
	if err != nil {
		t.Fatalf("PrepareNetns: %v", err)
	}

	if !mgr.IsEnforced("helper0000000000") {
		t.Fatal("helper should be enforced after PrepareNetns")
	}

	// Simulate DNS activity from the helper (e.g., git clone).
	// Find the netns context and record on the shared DNS recorder.
	mgr.mu.Lock()
	helperEnforcer := mgr.enforcers["helper0000000000"]
	mgr.mu.Unlock()

	if helperEnforcer == nil {
		t.Fatal("expected non-nil enforcer for helper")
	}

	nctx := helperEnforcer.ctx
	nctx.sharedDNSRecorder.RecordDNS("git.example.com", "A", "dns_observed", []string{"10.0.0.1"}, 42, "git", "bash", "")

	// Step 2: Build container starts — Attach joins the existing netns.
	buildInfo := ContainerInfo{
		ContainerID: "build00000000000",
		ProjectPath: "setl/setl",
		JobID:       "282913",
	}
	pol := testPolicy("audit")

	e, err := mgr.Attach(ctx, buildInfo, 101, pol)
	if err != nil {
		t.Fatalf("build Attach: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil enforcer for build")
	}

	// Verify build joined the same netns context.
	if e.ctx != nctx {
		t.Fatal("build should share netns context with helper")
	}

	// Step 3: Build exits — Detach should include sibling DNS activity.
	result := mgr.Detach("build00000000000")
	if result == nil {
		t.Fatal("expected non-nil detach result for build")
	}

	if result.Info.ProjectPath != "setl/setl" {
		t.Errorf("project = %q, want setl/setl", result.Info.ProjectPath)
	}

	// DNS activity from the shared recorder should be present.
	if len(result.Stats.DNSActivity) != 1 {
		t.Errorf("dns activity = %d, want 1 (git.example.com)", len(result.Stats.DNSActivity))
	} else if result.Stats.DNSActivity[0].Domain != "git.example.com" {
		t.Errorf("dns domain = %q, want git.example.com", result.Stats.DNSActivity[0].Domain)
	}

	// No DNS violations — DNS events are activity only.
	if len(result.Stats.Violations) != 0 {
		t.Errorf("violations = %d, want 0 (DNS events are activity only)", len(result.Stats.Violations))
	}
}

// TestPrepareNetns_BuildJoinUpdatesEBPFMode verifies that when a helper
// container prepares the netns in audit mode and the build container joins
// with a block-mode policy, the eBPF config map is updated to block mode.
func TestPrepareNetns_BuildJoinUpdatesEBPFMode(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 8888, 101: 8888},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	// Step 1: Helper container starts — PrepareNetns sets up in audit mode.
	err := mgr.PrepareNetns("helper0000000000", 100, "/sys/fs/cgroup/helper")
	if err != nil {
		t.Fatalf("PrepareNetns: %v", err)
	}

	// Grab the eBPF handle to inspect its mode later.
	mgr.mu.Lock()
	helperEnforcer := mgr.enforcers["helper0000000000"]
	mgr.mu.Unlock()

	if helperEnforcer == nil {
		t.Fatal("PrepareNetns did not register a helper enforcer")
	}

	nctx := helperEnforcer.ctx
	ebpfHandle := nctx.ebpf.(*fakeEBPFHandle)

	// Verify initial state: audit mode, SetMode not yet called.
	if ebpfHandle.modeUpdated {
		t.Fatal("SetMode should not have been called during PrepareNetns")
	}

	if !nctx.auditMode.Load() {
		t.Fatal("PrepareNetns should initialize in audit mode")
	}

	// Step 2: Build container joins with block-mode policy.
	buildInfo := ContainerInfo{
		ContainerID: "build00000000000",
		ProjectPath: "team/app",
		JobID:       "999",
	}

	e, err := mgr.Attach(context.Background(), buildInfo, 101, testPolicy("block"))
	if err != nil {
		t.Fatalf("build Attach: %v", err)
	}

	if e == nil {
		t.Fatal("expected non-nil enforcer for build")
	}

	// Verify: eBPF mode should have been updated to block (audit=false).
	if !ebpfHandle.modeUpdated {
		t.Fatal("Attach should call SetMode on the eBPF handle when the joiner's policy differs")
	}

	if ebpfHandle.auditMode {
		t.Fatal("eBPF mode should be block (audit=false) after build container joins with block policy")
	}
}

// TestPrepareNetns_RingbufReaderObservesLiveModeFlip pins the contract that
// the ringbuf reader's audit-mode source reflects the post-join state, not a
// value snapshotted at netns creation. Regression test for the bug where
// blocked packets in K8s pods (helper creates netns first → audit, build
// joins → block) were mislabelled "packet_observed" because the reader
// captured auditMode by value.
func TestPrepareNetns_RingbufReaderObservesLiveModeFlip(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 9999, 101: 9999},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	prepErr := mgr.PrepareNetns("helper0000000000", 100, "/sys/fs/cgroup/helper")
	if prepErr != nil {
		t.Fatalf("PrepareNetns: %v", prepErr)
	}

	mgr.mu.Lock()
	helperE := mgr.enforcers["helper0000000000"]
	mgr.mu.Unlock()
	if helperE == nil {
		t.Fatal("PrepareNetns did not register a helper enforcer")
	}

	handle := helperE.ctx.ebpf.(*fakeEBPFHandle)
	if handle.ringbufAuditSrc == nil {
		t.Fatal("StartRingbufReader did not receive an audit-mode source")
	}

	if !handle.ringbufAuditSrc.Load() {
		t.Fatal("ringbuf reader should observe audit=true initially (helper-created netns)")
	}

	_, attachErr := mgr.Attach(context.Background(),
		ContainerInfo{ContainerID: "build00000000000", ProjectPath: "team/app", JobID: "1"},
		101, testPolicy("block"))
	if attachErr != nil {
		t.Fatalf("build Attach: %v", attachErr)
	}

	if handle.ringbufAuditSrc.Load() {
		t.Fatal("ringbuf reader still observes audit=true after build joined with block policy;" +
			" drop events will be mislabelled packet_observed instead of packet_dropped")
	}
}

func TestPrepareNetns_SiblingDetachSuppressesReport(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	err := mgr.PrepareNetns("helper0000000000", 100, "/sys/fs/cgroup/helper")
	if err != nil {
		t.Fatalf("PrepareNetns: %v", err)
	}

	// Detach sibling — result should have empty ProjectPath.
	result := mgr.Detach("helper0000000000")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Info.ProjectPath != "" {
		t.Errorf("sibling project = %q, want empty", result.Info.ProjectPath)
	}
}

// TestInitContainerExitsBeforeBuild reproduces the GitLab Runner K8s lifecycle
// where init-permissions (with CI metadata) exits before the build container
// starts. The build container's DNS activity must be captured in the report.
//
// Real-world sequence:
//  1. init-permissions starts → Attach (has CI_PROJECT_PATH, project="team/leitwacht")
//  2. init-permissions exits  → Detach → report sent with 0 DNS (too early!)
//  3. build starts            → PrepareNetns or Attach (no CI_PROJECT_PATH)
//  4. build makes DNS queries → should be captured
//  5. build exits             → Detach → report should include DNS from step 4
//
// Currently fails: init-permissions detach tears down the netns, so the build
// container's DNS queries are never captured.
func TestInitContainerExitsBeforeBuild(t *testing.T) {
	// Both containers share the same pod netns (inode 7777).
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 7777, 200: 7777},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 100 * time.Millisecond // short grace for test
	defer mgr.DetachAll()
	ctx := context.Background()

	// Step 1: init-permissions starts — has CI metadata, gets full Attach.
	initInfo := ContainerInfo{
		ContainerID: "initperms00000",
		ProjectPath: "team/leitwacht-runner",
		JobID:       "283264",
		PipelineID:  "99999",
	}
	pol := testPolicy("audit")

	initE, err := mgr.Attach(ctx, initInfo, 100, pol)
	if err != nil {
		t.Fatalf("init Attach: %v", err)
	}
	if initE == nil {
		t.Fatal("expected non-nil enforcer for init")
	}

	// Step 2: init-permissions exits immediately (lives ~1.5s in prod).
	initResult := mgr.Detach("initperms00000")
	if initResult == nil {
		t.Fatal("expected non-nil detach result for init")
	}
	t.Logf("init detach: violations=%d dns=%d", len(initResult.Stats.Violations), len(initResult.Stats.DNSActivity))

	// Step 3: build container starts — no CI_PROJECT_PATH, treated as sibling.
	// In production this goes through HandleSiblingStart → PrepareNetns.
	// But PrepareNetns will find netns 7777 already torn down (init detach
	// dropped refcount to 0).
	//
	// The fix should keep the netns alive when siblings are expected, OR
	// allow the build container to re-establish the netns context.
	buildErr := mgr.PrepareNetns("build000000000000", 200, "/sys/fs/cgroup/build")

	// After PrepareNetns (or Attach), the build container should be tracked.
	if buildErr != nil {
		t.Logf("PrepareNetns for build: %v (this is the bug — netns was torn down)", buildErr)
	}

	// Try Attach as fallback (build container might go through HandleStart
	// if metadata becomes available later).
	if !mgr.IsEnforced("build000000000000") {
		buildInfo := ContainerInfo{
			ContainerID: "build000000000000",
			ProjectPath: "", // no metadata
		}
		auditPol := &policy.ResolvedPolicy{
			Action:   "audit",
			RuleSets: map[string][]policy.Rule{"": nil},
		}
		auditPol.BuildLookups()

		_, attachErr := mgr.Attach(ctx, buildInfo, 200, auditPol)
		if attachErr != nil {
			t.Logf("build Attach fallback: %v", attachErr)
		}
	}

	if !mgr.IsEnforced("build000000000000") {
		t.Fatal("build container should be enforced — netns was torn down prematurely")
	}

	// Step 4: build makes DNS queries.
	mgr.mu.Lock()
	buildE := mgr.enforcers["build000000000000"]
	mgr.mu.Unlock()

	if buildE == nil {
		t.Fatal("build enforcer is nil")
	}
	buildE.ctx.sharedDNSRecorder.RecordDNS("proxy.golang.org", "A", "dns_allowed", []string{"142.250.80.17"}, 300, "go", "sh", "")

	// Step 5: build exits.
	buildResult := mgr.Detach("build000000000000")
	if buildResult == nil {
		t.Fatal("expected non-nil detach result for build")
	}

	// The shared DNS recorder should contain the build's DNS query.
	// This is the key assertion: DNS from the build container must be reported.
	if len(buildResult.Stats.DNSActivity) == 0 {
		t.Fatal("build detach has 0 DNS activity — DNS from build container was lost")
	}

	found := false
	for _, dns := range buildResult.Stats.DNSActivity {
		t.Logf("  build dns: domain=%s", dns.Domain)
		if dns.Domain == "proxy.golang.org" {
			found = true
		}
	}
	if !found {
		t.Error("expected proxy.golang.org in build's DNS activity")
	}

	// Wait for deferred teardown goroutine to complete (avoids goroutine leak).
	time.Sleep(200 * time.Millisecond)
}

func TestPrepareNetns_IdempotentWhenAlreadyPrepared(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 9999, 101: 9999},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	defer mgr.DetachAll()

	err := mgr.PrepareNetns("helper0000000000", 100, "/sys/fs/cgroup/helper")
	if err != nil {
		t.Fatalf("PrepareNetns: %v", err)
	}

	// Second call for a different container in the same netns should join the
	// existing context (register cgroup, bump refcount).
	err = mgr.PrepareNetns("svc000000000000", 101, "/sys/fs/cgroup/svc")
	if err != nil {
		t.Fatalf("second PrepareNetns: %v", err)
	}

	// Both siblings should be tracked as enforcers sharing the same netns.
	if mgr.Count() != 2 {
		t.Errorf("enforcer count = %d, want 2", mgr.Count())
	}
}

// TestSiblingDenyIPsDoNotLeakAcrossDetach verifies T5: when a sibling
// detaches, its policy deny IPs are removed from the eBPF deny map so
// a later joiner with a disjoint deny list does not inherit them. The
// sinkhole entry survives — it's owned by the netns lifetime, not by
// any joiner.
func TestSiblingDenyIPsDoNotLeakAcrossDetach(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{
			100: 4242,
			101: 4242,
		},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0
	defer mgr.DetachAll()

	ctx := context.Background()

	blockPol := testPolicy("block")
	blockPol.DenyIPs = []policy.DenyIP{{IP: "10.0.0.1", Port: 443}}

	allowPol := testPolicy("audit")
	allowPol.DenyIPs = nil

	// Creator with deny IP.
	_, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "creator00000"}, 100, blockPol)
	if err != nil {
		t.Fatalf("creator attach: %v", err)
	}

	if !contains(fp.deniedIPs, "10.0.0.1:443") {
		t.Fatalf("expected creator's deny IP in map, got %v", fp.deniedIPs)
	}

	// Detach creator. Its deny IP must go.
	mgr.Detach("creator00000")

	if contains(fp.deniedIPs, "10.0.0.1:443") {
		t.Fatalf("creator's deny IP leaked after detach: %v", fp.deniedIPs)
	}

	// Sinkhole survives — it's the netns-lifetime entry.
	if !contains(fp.deniedIPs, SinkholeIPv4+":0") {
		t.Fatalf("sinkhole should survive joiner detach, got %v", fp.deniedIPs)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
