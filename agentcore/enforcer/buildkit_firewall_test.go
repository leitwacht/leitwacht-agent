//go:build linux

package enforcer

import (
	"errors"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// fakeFirewallInstaller captures calls from setupBuildkitDNSFirewall without
// touching the kernel, so tests can run unprivileged.
type fakeFirewallInstaller struct {
	installCalls int
	removeCalls  int
	lastIP       net.IP
	installErr   error
	removeErr    error
}

func (f *fakeFirewallInstaller) install(listenIP net.IP) error {
	f.installCalls++
	f.lastIP = listenIP

	return f.installErr
}

func (f *fakeFirewallInstaller) remove() error {
	f.removeCalls++

	return f.removeErr
}

func TestBuildkitFirewallSkipsLoopback(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
	}{
		{"loopback v4", net.ParseIP("127.0.0.1")},
		{"loopback alt", net.ParseIP("127.0.0.53")},
		{"unspecified v4", net.ParseIP("0.0.0.0")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := &fakeFirewallInstaller{}

			err := setupBuildkitDNSFirewallWith(inst, tc.ip, testBuildkitLogger())
			if err != nil {
				t.Fatalf("expected nil for %s, got: %v", tc.ip, err)
			}

			if inst.installCalls != 0 {
				t.Errorf("installer should not be called for %s, got %d calls", tc.ip, inst.installCalls)
			}
		})
	}
}

func TestBuildkitFirewallInstallsForRoutableIP(t *testing.T) {
	inst := &fakeFirewallInstaller{}

	ip := net.ParseIP("10.0.0.42")

	err := setupBuildkitDNSFirewallWith(inst, ip, testBuildkitLogger())
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if inst.installCalls != 1 {
		t.Errorf("installer should be called once, got %d", inst.installCalls)
	}

	if !inst.lastIP.Equal(ip) {
		t.Errorf("installer got ip=%s, want %s", inst.lastIP, ip)
	}
}

func TestBuildkitFirewallPropagatesInstallError(t *testing.T) {
	wantErr := errors.New("install boom")
	inst := &fakeFirewallInstaller{installErr: wantErr}

	err := setupBuildkitDNSFirewallWith(inst, net.ParseIP("10.1.2.3"), testBuildkitLogger())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped install error, got: %v", err)
	}
}

func TestBuildkitFirewallRules_TableAndChain(t *testing.T) {
	table, chain, _ := buildkitDNSFirewallRules(net.ParseIP("10.0.0.42").To4())

	if table.Name != "leitwacht_buildkit_dns" {
		t.Errorf("table name = %q, want leitwacht_buildkit_dns", table.Name)
	}

	if table.Family != nftables.TableFamilyINet {
		t.Errorf("table family = %v, want inet", table.Family)
	}

	if chain.Name != "input_filter" {
		t.Errorf("chain name = %q, want input_filter", chain.Name)
	}

	if chain.Type != nftables.ChainTypeFilter {
		t.Errorf("chain type = %q, want filter", chain.Type)
	}

	if chain.Hooknum != nftables.ChainHookInput {
		t.Errorf("chain hook mismatch, want input")
	}

	if chain.Priority == nil || *chain.Priority != -100 {
		t.Errorf("chain priority = %v, want -100", chain.Priority)
	}
}

func TestBuildkitFirewallRules_AcceptLoopbackFirst(t *testing.T) {
	_, _, rules := buildkitDNSFirewallRules(net.ParseIP("10.0.0.42").To4())

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (lo accept, udp drop, tcp drop), got %d", len(rules))
	}

	last := rules[0].Exprs[len(rules[0].Exprs)-1]

	v, ok := last.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Errorf("rule 0 verdict = %+v, want accept", last)
	}
}

func TestBuildkitFirewallRules_DropRulesShape(t *testing.T) {
	ip := net.ParseIP("10.0.0.42").To4()
	_, _, rules := buildkitDNSFirewallRules(ip)

	for i := 1; i <= 2; i++ {
		assertDropRule(t, rules[i], ip, i)
	}
}

// assertDropRule checks that rule carries a Counter, ends in Verdict{Drop}, and
// matches the listen IP. Split out of the table-test loop to keep each
// assertion path under gocognit's threshold.
func assertDropRule(t *testing.T, rule *nftables.Rule, ip net.IP, idx int) {
	t.Helper()

	if !hasCounter(rule.Exprs) {
		t.Errorf("rule %d missing counter expression", idx)
	}

	last := rule.Exprs[len(rule.Exprs)-1]

	v, ok := last.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictDrop {
		t.Errorf("rule %d verdict = %+v, want drop", idx, last)
	}

	if !matchesListenIP(rule.Exprs, ip) {
		t.Errorf("rule %d does not match listen IP %s", idx, ip)
	}
}

func hasCounter(exprs []expr.Any) bool {
	for _, e := range exprs {
		if _, ok := e.(*expr.Counter); ok {
			return true
		}
	}

	return false
}

func matchesListenIP(exprs []expr.Any, ip net.IP) bool {
	const ipv4Len = 4

	for _, e := range exprs {
		c, ok := e.(*expr.Cmp)
		if !ok {
			continue
		}

		if len(c.Data) == ipv4Len && net.IP(c.Data).Equal(ip) {
			return true
		}
	}

	return false
}
