//go:build linux && integration

package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// TestIntegrationEgressProgramLoads is the cheapest possible check on
// the thing that breaks hardest: the egress program has to pass the
// kernel verifier on the running kernel, and every map has to be created
// with the value size userspace writes.
//
// The CI drift check only proves the committed artefacts match the C
// source — it compiles nothing into a kernel. A verifier rejection or a
// map value-size mismatch (u8 vs u32) would sail past it and fail at
// attach time on a real host instead.
//
// Needs root but no container runtime, so it runs anywhere.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationEgressProgramLoads -v -count=1.
func TestIntegrationEgressProgramLoads(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	platform := &LinuxPlatform{Logger: logger}

	_, trusted, err := net.ParseCIDR("172.17.0.0/16")
	if err != nil {
		t.Fatalf("parse trusted cidr: %v", err)
	}

	handle, err := platform.LoadEBPF(false, []net.IPNet{*trusted})
	if err != nil {
		t.Fatalf("load ebpf — the egress program did not verify on kernel %s: %v", kernelRelease(), err)
	}

	defer func() { _ = handle.Close() }()

	ip := net.ParseIP(ipRuleTestIP)

	// Each Put exercises a different map with the priority-sized value.
	// A stale u8 value size surfaces here as EINVAL rather than as a
	// mysterious non-enforcing agent in production.
	if err = handle.AddAllowedHost(ip, 443, policy.RulePriority(0)); err != nil {
		t.Fatalf("add static allow: %v", err)
	}

	if err = handle.AddAllowedIP(ip, []int{443}, policy.RulePriority(1)); err != nil {
		t.Fatalf("add dns-derived allow: %v", err)
	}

	if err = handle.AddDeniedIP(ip, 0, policy.SystemRulePriority); err != nil {
		t.Fatalf("add deny: %v", err)
	}

	// Removal must be idempotent — Detach calls it for containers that
	// never installed anything.
	if err = handle.RemoveAllowedHost(ip, 443); err != nil {
		t.Fatalf("remove static allow: %v", err)
	}

	if err = handle.RemoveAllowedHost(ip, 443); err != nil {
		t.Fatalf("remove static allow (second call must be a no-op): %v", err)
	}

	if err = handle.RemoveDeniedIP(ip, 0); err != nil {
		t.Fatalf("remove deny: %v", err)
	}
}

func kernelRelease() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}

	return strings.TrimSpace(string(out))
}

// TEST-NET-2 (RFC 5737) — never routed on the public internet, and
// outside both the sinkhole range (192.0.2.0/24) and anything DNS could
// put in the allow map. Same address family as TestIntegrationBareIPBlocked,
// which is the negative twin of these tests.
const ipRuleTestIP = "198.51.100.2"

// startTestContainer boots a detached alpine container running script
// and returns its host PID, registering teardown on t.
//
// Either containerd or podman will do — the enforcer attaches by PID and
// cgroup path, so the runtime that created the container is irrelevant
// to what's under test. Accepting both is what lets these run on hosts
// that carry only one of them.
func startTestContainer(t *testing.T, name, script string) int {
	t.Helper()

	const testImage = "docker.io/library/alpine:latest"

	if _, err := exec.LookPath("ctr"); err == nil {
		_ = exec.Command("ctr", "image", "pull", testImage).Run()
		_ = exec.Command("ctr", "task", "kill", "-s", "9", name).Run()
		_ = exec.Command("ctr", "task", "delete", name).Run()
		_ = exec.Command("ctr", "container", "delete", name).Run()

		out, runErr := exec.Command("ctr", "run", "-d", "--net-host=false", testImage, name,
			"sh", "-c", script).CombinedOutput()
		if runErr != nil {
			t.Fatalf("ctr run: %v\n%s", runErr, out)
		}

		t.Cleanup(func() {
			_ = exec.Command("ctr", "task", "kill", "-s", "9", name).Run()
			time.Sleep(100 * time.Millisecond)
			_ = exec.Command("ctr", "task", "delete", name).Run()
			_ = exec.Command("ctr", "container", "delete", name).Run()
		})

		return getTaskPID(t, name)
	}

	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("neither ctr nor podman found, requires a container runtime")
	}

	_ = exec.Command("podman", "rm", "-f", name).Run()

	out, runErr := exec.Command("podman", "run", "-d", "--name", name, testImage,
		"sh", "-c", script).CombinedOutput()
	if runErr != nil {
		t.Fatalf("podman run: %v\n%s", runErr, out)
	}

	t.Cleanup(func() {
		_ = exec.Command("podman", "rm", "-f", name).Run()
	})

	pidOut, inspectErr := exec.Command("podman", "inspect", "-f", "{{.State.Pid}}", name).Output()
	if inspectErr != nil {
		t.Fatalf("podman inspect: %v", inspectErr)
	}

	pid, convErr := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	if convErr != nil {
		t.Fatalf("parse podman pid %q: %v", pidOut, convErr)
	}

	return pid
}

// runBareIPScenario boots an alpine container that dials ipRuleTestIP
// directly (no DNS at all), attaches the enforcer with the given rules,
// and returns the violations observed at detach.
//
// The IP is pinned to the container's loopback so the kernel actually
// builds and dispatches the SYN. Without the route, connect() fails with
// ENETUNREACH before cgroup_skb runs and the assertions below would pass
// for entirely the wrong reason.
func runBareIPScenario(t *testing.T, name string, rules []policy.Rule) []Violation {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	container := "leitwacht-integ-" + name

	// Dial in a loop so the traffic is still flowing when the enforcer
	// attaches — a single early nc could race the attach and produce a
	// false "allowed" result.
	script := "while true; do nc -z -w 2 " + ipRuleTestIP + " 80 >/dev/null 2>&1 || true; sleep 2; done"

	pid := startTestContainer(t, container, script)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	netns := fmt.Sprintf("--net=/proc/%d/ns/net", pid)

	loUp := exec.Command("nsenter", netns, "ip", "link", "set", "lo", "up")
	if loOut, loErr := loUp.CombinedOutput(); loErr != nil {
		t.Fatalf("bring up loopback: %v\n%s", loErr, loOut)
	}

	route := exec.Command("nsenter", netns, "ip", "route", "add", ipRuleTestIP, "dev", "lo")
	if routeOut, routeErr := route.CombinedOutput(); routeErr != nil {
		t.Fatalf("add bare-IP route: %v\n%s", routeErr, routeOut)
	}

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if startErr := mgr.StartDNSPIDTracker(); startErr != nil {
		t.Fatalf("start dns pid tracker: %v", startErr)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/" + name,
		Action:      "block",
		RuleSets:    map[string][]policy.Rule{"": rules},
	}
	pol.BuildLookups()

	info := ContainerInfo{ContainerID: container + "000", ProjectPath: pol.ProjectPath}

	if _, attachErr := mgr.Attach(context.Background(), info, pid, pol); attachErr != nil {
		t.Fatalf("attach: %v", attachErr)
	}

	t.Log("waiting for nc → bare-IP → eBPF verdict...")
	time.Sleep(10 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	for i := range result.Stats.Violations {
		v := &result.Stats.Violations[i]
		t.Logf("  viol: ip=%s port=%d action=%s comm=%q", v.IP, v.Port, v.Action, v.Comm)
	}

	return result.Stats.Violations
}

// TestIntegrationDNSAllowUnaffectedByPriority is a regression guard on
// the half of this change that isn't new behaviour: DNS-derived allow
// entries went from a bare presence flag to a priority value, and if
// that write is wrong every monitored job silently loses egress to
// domains it is supposed to reach.
//
// Uses a real domain through the proxy, matching the rest of the
// integration suite (see the httpbin.org note in tests/e2e/run.sh).
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationDNSAllowUnaffectedByPriority -v -count=1.
func TestIntegrationDNSAllowUnaffectedByPriority(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	const allowedDomain = "example.com"

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	script := "while true; do nc -z -w 3 " + allowedDomain + " 80 >/dev/null 2>&1 || true; sleep 2; done"

	pid := startTestContainer(t, "leitwacht-integ-dnsallow", script)
	if pid == 0 {
		t.Fatal("could not find container PID")
	}

	platform := &LinuxPlatform{Logger: logger}
	mgr := NewManager(logger, 32, []string{"1.1.1.1:53"}, nil, platform, CredwatchConfig{}, ProcMemConfig{})

	if err := mgr.StartDNSPIDTracker(); err != nil {
		t.Fatalf("start dns pid tracker: %v", err)
	}

	t.Cleanup(func() {
		mgr.DetachAll()
		mgr.StopDNSPIDTracker()
	})

	pol := &policy.ResolvedPolicy{
		ProjectPath: "test/dnsallow",
		Action:      "block",
		RuleSets: map[string][]policy.Rule{"": {{
			Pattern:     allowedDomain,
			PatternType: policy.PatternFQDN,
			Action:      policy.ActionAllow,
			Ports:       []int{80, 443},
		}}},
	}
	pol.BuildLookups()

	info := ContainerInfo{ContainerID: "leitwacht-integ-dnsallow000", ProjectPath: pol.ProjectPath}

	if _, err := mgr.Attach(context.Background(), info, pid, pol); err != nil {
		t.Fatalf("attach: %v", err)
	}

	t.Log("waiting for DNS resolve → allow-map seed → connect...")
	time.Sleep(15 * time.Second)

	result := mgr.Detach(info.ContainerID)
	if result == nil {
		t.Fatal("expected non-nil detach result")
	}

	var resolvedIPs []string

	for _, d := range result.Stats.DNSActivity {
		t.Logf("  dns: domain=%s action=%s ips=%v", d.Domain, d.Action, d.ResolvedIPs)

		if strings.Contains(d.Domain, allowedDomain) && d.Action == "dns_allowed" {
			resolvedIPs = append(resolvedIPs, d.ResolvedIPs...)
		}
	}

	if len(resolvedIPs) == 0 {
		t.Fatalf("no dns_allowed activity for %s — the proxy did not allow the query, "+
			"so this run proves nothing about the allow map", allowedDomain)
	}

	for i := range result.Stats.Violations {
		v := &result.Stats.Violations[i]
		t.Logf("  viol: ip=%s port=%d action=%s", v.IP, v.Port, v.Action)

		for _, ip := range resolvedIPs {
			if v.IP == ip {
				t.Fatalf("packet to %s (resolved from %s) was dropped with action=%q — "+
					"the priority-stamped allow-map seed is not being honoured",
					ip, allowedDomain, v.Action)
			}
		}
	}
}

func violationForIP(violations []Violation, ip string) *Violation {
	for i := range violations {
		if violations[i].IP == ip {
			return &violations[i]
		}
	}

	return nil
}

// TestIntegrationBareIPAllowedByCIDRRule is the positive counterpart of
// TestIntegrationBareIPBlocked: with a cidr allow rule in the job's rule
// set, a destination that has no DNS name at all must be reachable.
//
// This is the case the product could not express before — a deploy step
// whose target is an address, not a name, had no way through block mode
// short of a node-wide TRUSTED_CIDRS entry.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationBareIPAllowedByCIDRRule -v -count=1.
func TestIntegrationBareIPAllowedByCIDRRule(t *testing.T) {
	violations := runBareIPScenario(t, "ipallow", []policy.Rule{{
		Pattern:     ipRuleTestIP + "/32",
		PatternType: policy.PatternCIDR,
		Action:      policy.ActionAllow,
		Ports:       []int{80},
	}})

	if v := violationForIP(violations, ipRuleTestIP); v != nil {
		t.Fatalf("cidr allow rule did not permit %s — got violation action=%q port=%d; "+
			"the static allow map was not seeded, or egress.c is not consulting it",
			ipRuleTestIP, v.Action, v.Port)
	}
}

// TestIntegrationIPRuleOrdering pins first-match-wins for IP rules: a
// deny above an allow must win, and an allow above a deny must win. The
// datapath used to hardcode deny-beats-allow regardless of position,
// which diverged from how the DNS proxy treats fqdn rules.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationIPRuleOrdering -v -count=1.
func TestIntegrationIPRuleOrdering(t *testing.T) {
	allowRule := policy.Rule{
		Pattern:     ipRuleTestIP + "/32",
		PatternType: policy.PatternCIDR,
		Action:      policy.ActionAllow,
		Ports:       []int{80},
	}

	denyRule := policy.Rule{
		Pattern:     ipRuleTestIP + "/32",
		PatternType: policy.PatternCIDR,
		Action:      policy.ActionDeny,
	}

	t.Run("deny above allow blocks", func(t *testing.T) {
		violations := runBareIPScenario(t, "ipdenyfirst", []policy.Rule{denyRule, allowRule})

		if violationForIP(violations, ipRuleTestIP) == nil {
			t.Fatalf("deny rule above allow did not block %s — rule order was not honoured",
				ipRuleTestIP)
		}
	})

	t.Run("allow above deny permits", func(t *testing.T) {
		violations := runBareIPScenario(t, "ipallowfirst", []policy.Rule{allowRule, denyRule})

		if v := violationForIP(violations, ipRuleTestIP); v != nil {
			t.Fatalf("allow rule above deny did not permit %s (action=%q) — "+
				"the datapath is still hardcoding deny-beats-allow", ipRuleTestIP, v.Action)
		}
	})
}
