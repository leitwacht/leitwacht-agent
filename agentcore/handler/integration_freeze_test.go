//go:build linux && integration

package handler

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/watcher"
)

func itImage() string {
	if v := os.Getenv("LEITWACHT_TEST_IMAGE"); v != "" {
		return v
	}

	return "docker.io/library/alpine:3.21"
}

// itContainer starts a --network=none busy-loop container (no host
// network or firewall is touched) and returns its PID. Podman only, no log
// driver; removes only the exact name it created.
func itContainer(t *testing.T, name string) int {
	t.Helper()

	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found")
	}

	_ = exec.Command("podman", "rm", "-f", name).Run()

	out, err := exec.Command("podman", "run", "-d", "--log-driver=none", "--name", name,
		"--network", "none", itImage(), "sh", "-c", "while :; do :; done").CombinedOutput()
	if err != nil {
		t.Fatalf("podman run: %v\n%s", err, out)
	}

	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", name).Run() })

	pidOut, err := exec.Command("podman", "inspect", "-f", "{{.State.Pid}}", name).Output()
	if err != nil {
		t.Fatalf("podman inspect: %v", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	if err != nil || pid <= 0 {
		t.Fatalf("parse pid %q: %v", pidOut, err)
	}

	return pid
}

func cpuUsageUsec(t *testing.T, cgroup string) int64 {
	t.Helper()

	b, err := os.ReadFile(cgroup + "/cpu.stat")
	if err != nil {
		t.Fatalf("read cpu.stat: %v", err)
	}

	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)

			return n
		}
	}

	t.Fatal("no usage_usec in cpu.stat")

	return 0
}

func containerRunning(name string) bool {
	out, err := exec.Command("podman", "inspect", "-f", "{{.State.Running}}", name).Output()

	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// TestIntegrationFreezerHoldsRealContainer proves the cgroup freezer
// actually stops a CPU-bound container (usage stops advancing) and that
// Thaw resumes it.
//
// Run: sudo -E go test ./agentcore/handler/ -tags integration -run TestIntegrationFreezerHoldsRealContainer -v -count=1.
func TestIntegrationFreezerHoldsRealContainer(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	const name = "leitwacht-integ-freezer"

	pid := itContainer(t, name)

	cg, err := (&enforcer.LinuxPlatform{Logger: quietLogger()}).GetCgroupPath(pid)
	if err != nil {
		t.Fatalf("cgroup path: %v", err)
	}

	cg = enforcer.ScopeCgroup(cg)

	time.Sleep(200 * time.Millisecond)

	if run := cpuUsageUsec(t, cg); run <= 0 {
		t.Fatal("busy container shows no cpu usage before the freeze")
	}

	f := &Freezer{Logger: quietLogger(), StateDir: t.TempDir()}

	z, err := f.Freeze(context.Background(), name, cg, 5*time.Second)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	before := cpuUsageUsec(t, cg)

	time.Sleep(300 * time.Millisecond)

	if delta := cpuUsageUsec(t, cg) - before; delta > 20_000 {
		t.Fatalf("container consumed %dus of cpu while frozen", delta)
	}

	z.Thaw()

	before = cpuUsageUsec(t, cg)

	time.Sleep(300 * time.Millisecond)

	if delta := cpuUsageUsec(t, cg) - before; delta < 50_000 {
		t.Fatalf("container did not resume after Thaw (cpu delta %dus)", delta)
	}
}

// failLoadPlatform is the real platform with the eBPF load forced to fail,
// recording whether the container's cgroup was frozen at that moment.
type failLoadPlatform struct {
	*enforcer.LinuxPlatform
	mu           sync.Mutex
	frozenAtLoad bool
	cgroup       string
}

func (p *failLoadPlatform) LoadEBPF(bool, []net.IPNet) (enforcer.EBPFHandle, error) {
	b, _ := os.ReadFile(p.cgroup + "/cgroup.events")

	p.mu.Lock()
	p.frozenAtLoad = strings.Contains(string(b), "frozen 1")
	p.mu.Unlock()

	return nil, errors.New("synthetic ebpf load failure")
}

type podmanKiller struct{ fakeWatcher }

func (*podmanKiller) KillContainer(_ context.Context, id string) error {
	return exec.Command("podman", "kill", id).Run()
}

// TestIntegrationBlockModeKillsOnAttachFailure drives HandleStart against a
// real podman container with enforcement forced to fail: in block mode the
// container must have been frozen while attach ran, then be killed.
//
// Run: sudo -E go test ./agentcore/handler/ -tags integration -run TestIntegrationBlockModeKillsOnAttachFailure -v -count=1.
func TestIntegrationBlockModeKillsOnAttachFailure(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	const name = "leitwacht-integ-killfail"

	pid := itContainer(t, name)
	lp := &enforcer.LinuxPlatform{Logger: quietLogger()}

	cg, err := lp.GetCgroupPath(pid)
	if err != nil {
		t.Fatalf("cgroup path: %v", err)
	}

	plat := &failLoadPlatform{LinuxPlatform: lp, cgroup: enforcer.ScopeCgroup(cg)}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mgr := enforcer.NewManager(log, 8, []string{"127.0.0.1:53"}, nil, plat, enforcer.CredwatchConfig{}, enforcer.ProcMemConfig{})

	t.Cleanup(func() { mgr.DetachAll() })

	pol := &policy.ResolvedPolicy{ProjectPath: "team/app", Action: "block", Enrolled: true, RuleSets: map[string][]policy.Rule{"": nil}}
	pol.BuildLookups()

	adv := &advisoryLog{}
	h := &Handler{
		Watcher: &podmanKiller{}, Policy: fakePolicy{pol: pol}, Enforcer: mgr,
		ViolationSink: nopViolations{}, AdvisorySink: adv, Logger: log, DefaultAction: "block",
		FreezeStateDir: t.TempDir(),
	}

	h.HandleStart(context.Background(), watcher.ContainerEvent{
		Action: "start", ContainerID: name, ProjectPath: "team/app", PID: pid,
	})

	if !plat.frozenAtLoad {
		t.Error("container was not frozen while enforcement was being attached")
	}

	// kill is asynchronous; give the runtime a moment.
	deadline := time.Now().Add(5 * time.Second)
	for containerRunning(name) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}

	if containerRunning(name) {
		t.Fatal("block-mode container still running after attach failure")
	}

	if got := adv.actions(); len(got) != 1 || got[0] != "killed" {
		t.Fatalf("advisory actions = %v, want [killed]", got)
	}

	var _ advisory.Sink = adv
}

// TestIntegrationRecoverFrozenAfterAgentDeath freezes a real container,
// abandons the Freezer without thawing (the agent "crashed"), and checks a
// fresh Freezer on the same state dir thaws it.
//
// Run: sudo -E go test ./agentcore/handler/ -tags integration -run TestIntegrationRecoverFrozenAfterAgentDeath -v -count=1.
func TestIntegrationRecoverFrozenAfterAgentDeath(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	const name = "leitwacht-integ-recover"

	pid := itContainer(t, name)

	cg, err := (&enforcer.LinuxPlatform{Logger: quietLogger()}).GetCgroupPath(pid)
	if err != nil {
		t.Fatalf("cgroup path: %v", err)
	}

	cg = enforcer.ScopeCgroup(cg)
	state := t.TempDir()

	if _, err = (&Freezer{Logger: quietLogger(), StateDir: state}).Freeze(context.Background(), name, cg, 5*time.Second); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	before := cpuUsageUsec(t, cg)

	time.Sleep(200 * time.Millisecond)

	if delta := cpuUsageUsec(t, cg) - before; delta > 20_000 {
		t.Fatalf("container not frozen (cpu delta %dus)", delta)
	}

	if n := (&Freezer{Logger: quietLogger(), StateDir: state}).RecoverFrozen(context.Background()); n != 1 {
		t.Fatalf("RecoverFrozen processed %d markers, want 1", n)
	}

	before = cpuUsageUsec(t, cg)

	time.Sleep(300 * time.Millisecond)

	if delta := cpuUsageUsec(t, cg) - before; delta < 50_000 {
		t.Fatalf("container still stopped after recovery (cpu delta %dus)", delta)
	}
}
