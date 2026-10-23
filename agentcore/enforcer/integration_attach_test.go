//go:build linux && integration

package enforcer

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// testImage is the image the podman-backed attach tests run. Override with
// LEITWACHT_TEST_IMAGE on hosts that only carry another one locally.
func testImage() string {
	if v := os.Getenv("LEITWACHT_TEST_IMAGE"); v != "" {
		return v
	}

	return "docker.io/library/alpine:3.21"
}

// startPodmanContainer boots a detached container and returns its host PID.
// network is passed to --network ("none", or "container:<other>" to share
// that container's netns). Uses podman only, no logging driver (container
// output must not reach the journal), and removes only the exact name it
// created.
func startPodmanContainer(t *testing.T, name, network, script string) int {
	t.Helper()

	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found")
	}

	_ = exec.Command("podman", "rm", "-f", name).Run()

	out, err := exec.Command("podman", "run", "-d", "--log-driver=none", "--pull=missing", "--name", name,
		"--network", network, testImage(), "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("podman run %s: %v\n%s", name, err, out)
	}

	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", name).Run() })

	pidOut, err := exec.Command("podman", "inspect", "-f", "{{.State.Pid}}", name).Output()
	if err != nil {
		t.Fatalf("podman inspect %s: %v", name, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	if err != nil || pid <= 0 {
		t.Fatalf("parse pid %q: %v", pidOut, err)
	}

	return pid
}

// TestIntegrationAddAllowedIPKeepsBestPriority: a DNS-derived allow for
// an address already allowed at a better priority must not be displaced by
// a later, lower-ranked resolution, whatever order they arrive in.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationAddAllowedIPKeepsBestPriority -v -count=1.
func TestIntegrationAddAllowedIPKeepsBestPriority(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	handle, err := (&LinuxPlatform{Logger: logger}).LoadEBPF(false, nil)
	if err != nil {
		t.Fatalf("LoadEBPF: %v", err)
	}

	defer func() { _ = handle.Close() }()

	h, ok := handle.(*linuxEBPFHandle)
	if !ok {
		t.Fatalf("unexpected handle type %T", handle)
	}

	ip := net.ParseIP(ipRuleTestIP)
	key := PackAllowKey(ip, 443)

	for _, prio := range []uint32{5, 2, 9} {
		if err = handle.AddAllowedIP(ip, []int{443}, prio); err != nil {
			t.Fatalf("AddAllowedIP(%d): %v", prio, err)
		}
	}

	var got uint32
	if err = h.objs.AllowedIps.Lookup(key[:], &got); err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if got != 2 {
		t.Fatalf("allowed_ips prio = %d after puts 5,2,9; want the minimum, 2", got)
	}
}

// TestIntegrationSharedNetnsDenySurvivesSiblingDetach attaches two real
// containers that share one netns with the same cidr deny, detaches the
// first, and checks the deny is still in the kernel map for the second.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationSharedNetnsDenySurvivesSiblingDetach -v -count=1.
func TestIntegrationSharedNetnsDenySurvivesSiblingDetach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	const (
		first  = "leitwacht-integ-shared-a"
		second = "leitwacht-integ-shared-b"
	)

	pidA := startPodmanContainer(t, first, "none", "sleep 300")
	pidB := startPodmanContainer(t, second, "container:"+first, "sleep 300")

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, &LinuxPlatform{Logger: logger},
		CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	t.Cleanup(func() { mgr.DetachAll() })

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/shared",
		Action:      "block",
		RuleSets: map[string][]policy.Rule{"": {{
			Pattern: ipRuleTestIP + "/32", PatternType: policy.PatternCIDR, Action: policy.ActionDeny, Ports: []int{443},
		}}},
	}
	pol.BuildLookups()

	ctx := context.Background()

	idA, idB := first+"000", second+"000"

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: idA, ProjectPath: pol.ProjectPath}, pidA, pol); err != nil {
		t.Fatalf("attach A: %v", err)
	}

	eB, err := mgr.Attach(ctx, ContainerInfo{ContainerID: idB, ProjectPath: pol.ProjectPath}, pidB, pol)
	if err != nil {
		t.Fatalf("attach B: %v", err)
	}

	mgr.mu.Lock()
	eA := mgr.enforcers[idA]
	mgr.mu.Unlock()

	if eA == nil || eB.ctx != eA.ctx {
		t.Fatal("containers did not share a netns context; test setup is wrong")
	}

	h, ok := eB.ctx.ebpf.(*linuxEBPFHandle)
	if !ok {
		t.Fatalf("unexpected handle type %T", eB.ctx.ebpf)
	}

	key := PackAllowKey(net.ParseIP(ipRuleTestIP), 443)

	var prio uint32
	if err = h.objs.DeniedIps.Lookup(key[:], &prio); err != nil {
		t.Fatalf("deny entry missing after both attached: %v", err)
	}

	mgr.Detach(idA)

	if err = h.objs.DeniedIps.Lookup(key[:], &prio); err != nil {
		t.Fatalf("deny entry removed when a sibling detached; the remaining container fails open: %v", err)
	}
}
