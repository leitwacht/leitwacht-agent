package handler

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/watcher"
)

// fakePlatform is the minimum enforcer.Platform needed to drive
// Manager.Attach from a handler test. cgroupDir doubles as the fake
// container cgroup the freezer writes to; freezeAtLoad records the state
// of cgroup.freeze at the moment the eBPF program is loaded, i.e. while
// HandleStart is mid-attach.
type fakePlatform struct {
	cgroupDir string
	loadErr   error
	t         *testing.T

	mu           sync.Mutex
	freezeAtLoad string
}

func (p *fakePlatform) GetCgroupPath(int) (string, error)  { return p.cgroupDir, nil }
func (p *fakePlatform) NetnsInode(pid int) (uint64, error) { return uint64(pid), nil }

func (p *fakePlatform) BindInNetns(int, string) (net.PacketConn, net.Listener, error) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = udp.Close()

		return nil, nil, err
	}

	return udp, tcp, nil
}

func (p *fakePlatform) SetupDNSRedirect(int) error  { return nil }
func (p *fakePlatform) RemoveDNSRedirect(int) error { return nil }
func (p *fakePlatform) CgroupID(string) (uint64, error) {
	return 42, nil
}

func (p *fakePlatform) NewUpstreamDialer(int) (enforcer.UpstreamDialer, error) {
	return nil, errors.New("fake: no docker upstream") //nolint:err113 // test fake
}

func (p *fakePlatform) LoadEBPF(bool, []net.IPNet) (enforcer.EBPFHandle, error) {
	p.mu.Lock()
	p.freezeAtLoad = readFreezeFile(p.t, p.cgroupDir)
	p.mu.Unlock()

	if p.loadErr != nil {
		return nil, p.loadErr
	}

	return fakeHandle{}, nil
}

type fakeHandle struct{}

func (fakeHandle) AddAllowedIP(net.IP, []int, uint32) error         { return nil }
func (fakeHandle) AddAllowedHost(net.IP, int, uint32) error         { return nil }
func (fakeHandle) RemoveAllowedHost(net.IP, int) error              { return nil }
func (fakeHandle) FlushAllowedIPs() error                           { return nil }
func (fakeHandle) AddDeniedIP(net.IP, int, uint32) error            { return nil }
func (fakeHandle) RemoveDeniedIP(net.IP, int) error                 { return nil }
func (fakeHandle) ReadStats() int64                                 { return 0 }
func (fakeHandle) AttachCgroup(string) (enforcer.CgroupLink, error) { return fakeLink{}, nil }
func (fakeHandle) AddSockKnownCgroup(uint64) error                  { return nil }
func (fakeHandle) RemoveSockKnownCgroup(uint64)                     {}
func (fakeHandle) SetMode(bool) error                               { return nil }
func (fakeHandle) Close() error                                     { return nil }

func (fakeHandle) StartRingbufReader(
	context.Context, func(uint64) *enforcer.ViolationRecorder, *atomic.Bool,
) (func(), error) {
	return func() {}, nil
}

type fakeLink struct{}

func (fakeLink) Close() error { return nil }

type fakeWatcher struct {
	mu      sync.Mutex
	killed  []string
	killErr error
	runtime string
}

func (w *fakeWatcher) Watch(context.Context) <-chan watcher.ContainerEvent { return nil }
func (w *fakeWatcher) RecoverRunning(context.Context) ([]watcher.ContainerEvent, error) {
	return nil, nil
}
func (w *fakeWatcher) ChannelDepth() int { return 0 }

// Runtime defaults to the Docker API runtime, the only one that freezes.
func (w *fakeWatcher) Runtime() string {
	if w.runtime != "" {
		return w.runtime
	}

	return watcher.RuntimeDocker
}
func (w *fakeWatcher) Close() error { return nil }

func (w *fakeWatcher) KillContainer(_ context.Context, id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.killed = append(w.killed, id)

	return w.killErr
}

func (w *fakeWatcher) killCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.killed)
}

type fakePolicy struct{ pol *policy.ResolvedPolicy }

func (p fakePolicy) GetPolicy(context.Context, string) (*policy.ResolvedPolicy, error) {
	return p.pol, nil
}

type advisoryLog struct {
	mu   sync.Mutex
	list []advisory.Advisory
}

func (l *advisoryLog) ReportAdvisory(_ context.Context, a *advisory.Advisory) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.list = append(l.list, *a)

	return nil
}

func (l *advisoryLog) actions() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]string, 0, len(l.list))
	for _, a := range l.list {
		out = append(out, a.ActionTaken)
	}

	return out
}

type nopViolations struct{}

func (nopViolations) ReportAsync(context.Context, enforcer.ContainerInfo, *enforcer.EgressStats, bool, time.Time) {
}

type rig struct {
	h    *Handler
	w    *fakeWatcher
	adv  *advisoryLog
	plat *fakePlatform
	dir  string
	mgr  *enforcer.Manager
}

func newRig(t *testing.T, action string, loadErr error, frozenAtOnce bool, maxConc int) *rig {
	t.Helper()

	dir := fakeCgroup(t, frozenAtOnce)
	plat := &fakePlatform{cgroupDir: dir, loadErr: loadErr, t: t}
	log := quietLogger()

	mgr := enforcer.NewManager(log, maxConc, []string{"127.0.0.1:53"}, nil, plat,
		enforcer.CredwatchConfig{}, enforcer.ProcMemConfig{})
	mgr.NetnsGrace = 0

	t.Cleanup(func() { mgr.DetachAll() })

	pol := &policy.ResolvedPolicy{
		ProjectPath: "team/app",
		Action:      action,
		Enrolled:    true,
		RuleSets:    map[string][]policy.Rule{"": nil},
	}
	pol.BuildLookups()

	w := &fakeWatcher{}
	adv := &advisoryLog{}

	return &rig{
		h: &Handler{
			Watcher:        w,
			Policy:         fakePolicy{pol: pol},
			Enforcer:       mgr,
			ViolationSink:  nopViolations{},
			AdvisorySink:   adv,
			Logger:         log,
			DefaultAction:  action,
			FreezeTimeout:  200 * time.Millisecond,
			FreezeStateDir: t.TempDir(),
		},
		w: w, adv: adv, plat: plat, dir: dir, mgr: mgr,
	}
}

func startEvent(id string, pid int) watcher.ContainerEvent {
	return watcher.ContainerEvent{Action: "start", ContainerID: id, ProjectPath: "team/app", PID: pid}
}

func TestHandleStartFreezesDuringAttachAndThawsAfter(t *testing.T) {
	r := newRig(t, "block", nil, true, 8)

	r.h.HandleStart(context.Background(), startEvent("ctr-freeze-ok-0001", 4101))

	if r.plat.freezeAtLoad != "1" {
		t.Fatalf("cgroup.freeze = %q while attaching, want 1 (container must be held until attach)", r.plat.freezeAtLoad)
	}

	if got := readFreezeFile(t, r.dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after successful attach, want thawed", got)
	}

	if r.w.killCount() != 0 || len(r.adv.actions()) != 0 {
		t.Fatalf("clean attach produced kills=%d advisories=%v", r.w.killCount(), r.adv.actions())
	}
}

func TestHandleStartBlockModeAttachFailureKills(t *testing.T) {
	r := newRig(t, "block", errors.New("synthetic bpf load failure"), true, 8)

	r.h.HandleStart(context.Background(), startEvent("ctr-block-fail-0001", 4102))

	if r.w.killCount() != 1 {
		t.Fatalf("kills = %d, want 1: a block-mode container that could not be enforced must not run", r.w.killCount())
	}

	if got := r.adv.actions(); len(got) != 1 || got[0] != "killed" {
		t.Fatalf("advisory actions = %v, want [killed]", got)
	}

	if got := readFreezeFile(t, r.dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after failure, want thawed", got)
	}
}

func TestHandleStartAuditModeAttachFailureWarnsAndThaws(t *testing.T) {
	r := newRig(t, "audit", errors.New("synthetic bpf load failure"), true, 8)

	r.h.HandleStart(context.Background(), startEvent("ctr-audit-fail-0001", 4103))

	if r.w.killCount() != 0 {
		t.Fatal("audit mode must never kill on attach failure")
	}

	if got := r.adv.actions(); len(got) != 1 || got[0] != "warned" {
		t.Fatalf("advisory actions = %v, want [warned]", got)
	}

	if got := readFreezeFile(t, r.dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q, want thawed", got)
	}
}

func TestHandleStartBlockModeAtCapacityKills(t *testing.T) {
	r := newRig(t, "block", nil, true, 1)

	r.h.HandleStart(context.Background(), startEvent("ctr-capacity-one-001", 4104))

	if r.w.killCount() != 0 {
		t.Fatal("first container should attach")
	}

	r.h.HandleStart(context.Background(), startEvent("ctr-capacity-two-001", 4105))

	if r.w.killCount() != 1 {
		t.Fatalf("kills = %d, want 1: the container refused at capacity must not run unenforced", r.w.killCount())
	}
}

func TestHandleStartBlockModeFreezeTimeoutKills(t *testing.T) {
	r := newRig(t, "block", nil, false, 8) // cgroup never reports frozen
	r.h.FreezeTimeout = 30 * time.Millisecond

	r.h.HandleStart(context.Background(), startEvent("ctr-freeze-timeout-1", 4106))

	if r.w.killCount() != 1 {
		t.Fatalf("kills = %d, want 1 on freeze timeout in block mode", r.w.killCount())
	}

	if got := r.adv.actions(); len(got) != 1 || got[0] != "killed" {
		t.Fatalf("advisory actions = %v, want [killed]", got)
	}

	if got := readFreezeFile(t, r.dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q, want thawed after timeout", got)
	}
}

func TestHandleStartAuditModeFreezeTimeoutWarnsAndAttaches(t *testing.T) {
	r := newRig(t, "audit", nil, false, 8)
	r.h.FreezeTimeout = 30 * time.Millisecond

	r.h.HandleStart(context.Background(), startEvent("ctr-freeze-timeout-2", 4107))

	if r.w.killCount() != 0 {
		t.Fatal("audit mode must not kill on freeze timeout")
	}

	if got := r.adv.actions(); len(got) != 1 || got[0] != "warned" {
		t.Fatalf("advisory actions = %v, want [warned]", got)
	}

	if !r.mgr.IsEnforced("ctr-freeze-timeout-2") {
		t.Fatal("audit-mode container should still be attached after a freeze timeout")
	}
}

func TestHandleStartFreezeDisabled(t *testing.T) {
	r := newRig(t, "block", nil, true, 8)
	r.h.FreezeTimeout = -1

	r.h.HandleStart(context.Background(), startEvent("ctr-no-freeze-000001", 4108))

	if r.plat.freezeAtLoad != "0" {
		t.Fatalf("cgroup.freeze = %q during attach with freezing disabled, want untouched 0", r.plat.freezeAtLoad)
	}
}

func TestHandlerShutdownThawsHeldContainers(t *testing.T) {
	r := newRig(t, "block", nil, true, 8)

	if _, err := r.h.freezer().Freeze(context.Background(), "ctr-held", r.dir, time.Second); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if got := readFreezeFile(t, r.dir); got != "1" {
		t.Fatalf("cgroup.freeze = %q, want held", got)
	}

	r.h.Shutdown()

	if got := readFreezeFile(t, r.dir); got != "0" {
		t.Fatalf("cgroup.freeze = %q after Shutdown, want thawed", got)
	}
}

func TestKillFallsBackToCgroupKill(t *testing.T) {
	r := newRig(t, "block", errors.New("synthetic bpf load failure"), true, 8)
	r.w.killErr = errors.New("runtime kill unavailable")
	writeFile(t, filepath.Join(r.dir, "cgroup.kill"), "0")

	r.h.HandleStart(context.Background(), startEvent("ctr-kill-fallback-01", 4110))

	if got := r.adv.actions(); len(got) != 1 || got[0] != "killed" {
		t.Fatalf("advisory actions = %v, want [killed] via cgroup.kill", got)
	}

	b, _ := os.ReadFile(filepath.Join(r.dir, "cgroup.kill"))
	if strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("cgroup.kill = %q, want 1", b)
	}
}

func TestKillFailureIsReportedAsKillFailed(t *testing.T) {
	r := newRig(t, "block", errors.New("synthetic bpf load failure"), true, 8)
	r.w.killErr = errors.New("runtime kill unavailable") // and no cgroup.kill file

	r.h.HandleStart(context.Background(), startEvent("ctr-kill-failed-0001", 4111))

	if got := r.adv.actions(); len(got) != 1 || got[0] != "kill_failed" {
		t.Fatalf("advisory actions = %v, want [kill_failed]", got)
	}
}

func TestContainerScopeIgnoresPathsOutsideCgroupMount(t *testing.T) {
	h := &Handler{Logger: quietLogger()}

	if got := h.containerScope(watcher.ContainerEvent{CgroupPath: "kubepods.slice:cri-containerd:abc"}); got != "" {
		t.Fatalf("systemd-style spec path accepted: %q", got)
	}

	if got := h.containerScope(watcher.ContainerEvent{CgroupPath: "/etc/passwd"}); got != "" {
		t.Fatalf("non-cgroup path accepted: %q", got)
	}

	if got := h.containerScope(watcher.ContainerEvent{CgroupPath: "/sys/fs/cgroup/system.slice/docker-x.scope/init"}); got != "/sys/fs/cgroup/system.slice/docker-x.scope" {
		t.Fatalf("valid path = %q", got)
	}
}

// TestHandleStartNeverFreezesContainerd: K8s (containerd/CRI) events are
// gated by leitwacht-initc, never frozen, whatever else is true.
func TestHandleStartNeverFreezesContainerd(t *testing.T) {
	r := newRig(t, "block", nil, true, 8)
	r.w.runtime = watcher.RuntimeContainerd

	r.h.HandleStart(context.Background(), startEvent("ctr-k8s-no-freeze-001", 4120))

	if r.plat.freezeAtLoad != "0" {
		t.Fatalf("cgroup.freeze = %q during attach on a containerd event, want untouched 0", r.plat.freezeAtLoad)
	}

	if !r.mgr.IsEnforced("ctr-k8s-no-freeze-001") {
		t.Fatal("containerd container should still be attached")
	}
}

// A watcher that does not identify its runtime is not frozen.
func TestHandleStartUnknownRuntimeNotFrozen(t *testing.T) {
	r := newRig(t, "block", nil, true, 8)
	r.h.Watcher = unnamedWatcher{r.w}

	r.h.HandleStart(context.Background(), startEvent("ctr-unnamed-0000001", 4121))

	if r.plat.freezeAtLoad != "0" {
		t.Fatalf("cgroup.freeze = %q, want untouched for an unidentified runtime", r.plat.freezeAtLoad)
	}
}

// unnamedWatcher hides the Runtime method of the wrapped watcher.
type unnamedWatcher struct{ w *fakeWatcher }

func (u unnamedWatcher) Watch(ctx context.Context) <-chan watcher.ContainerEvent {
	return u.w.Watch(ctx)
}
func (u unnamedWatcher) RecoverRunning(ctx context.Context) ([]watcher.ContainerEvent, error) {
	return u.w.RecoverRunning(ctx)
}
func (u unnamedWatcher) KillContainer(ctx context.Context, id string) error {
	return u.w.KillContainer(ctx, id)
}
func (u unnamedWatcher) ChannelDepth() int { return 0 }
func (u unnamedWatcher) Close() error      { return nil }
