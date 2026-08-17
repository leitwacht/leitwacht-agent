package enforcer

import (
	"context"
	"testing"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// ipRulePolicy builds a policy whose default rule set is exactly rules,
// so a test can assert on composed-list ordering directly.
func ipRulePolicy(action string, rules ...policy.Rule) *policy.ResolvedPolicy {
	p := &policy.ResolvedPolicy{
		ProjectPath: "test/project",
		Action:      action,
		RuleSets:    map[string][]policy.Rule{"": rules},
	}
	p.BuildLookups()

	return p
}

func cidrRule(pattern, action string, ports ...int) policy.Rule {
	return policy.Rule{
		Pattern:     pattern,
		PatternType: policy.PatternCIDR,
		Action:      action,
		Ports:       ports,
	}
}

// TestCollectIPRulesOrdering is the core of the first-match-wins
// contract: the priority stamped on each entry must follow position in
// the composed list, not the rule's action. The datapath compares those
// numbers, so getting this backwards silently inverts an operator's
// ruleset.
func TestCollectIPRulesOrdering(t *testing.T) {
	tests := []struct {
		name          string
		rules         []policy.Rule
		wantAllowPrio uint32
		wantDenyPrio  uint32
	}{
		{
			name: "allow above deny wins",
			rules: []policy.Rule{
				cidrRule("10.0.0.1", policy.ActionAllow, 22),
				cidrRule("10.0.0.1", policy.ActionDeny, 22),
			},
			wantAllowPrio: 1,
			wantDenyPrio:  2,
		},
		{
			name: "deny above allow wins",
			rules: []policy.Rule{
				cidrRule("10.0.0.1", policy.ActionDeny, 22),
				cidrRule("10.0.0.1", policy.ActionAllow, 22),
			},
			wantAllowPrio: 2,
			wantDenyPrio:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deny, allow := collectIPRules(ipRulePolicy("block", tc.rules...), testLogger())

			if len(allow) != 1 || allow[0].Prio != tc.wantAllowPrio {
				t.Fatalf("allow entries = %+v, want single entry with prio %d", allow, tc.wantAllowPrio)
			}

			if len(deny) != 1 || deny[0].Prio != tc.wantDenyPrio {
				t.Fatalf("deny entries = %+v, want single entry with prio %d", deny, tc.wantDenyPrio)
			}
		})
	}
}

// TestCollectIPRulesDuplicateKeepsFirst guards the overwrite hazard:
// each eBPF map holds one value per key, so a later duplicate rule must
// not replace an earlier rule's priority with a worse one.
func TestCollectIPRulesDuplicateKeepsFirst(t *testing.T) {
	_, allow := collectIPRules(
		ipRulePolicy("block",
			cidrRule("10.0.0.1", policy.ActionAllow, 22),
			cidrRule("10.0.0.1", policy.ActionAllow, 22),
		),
		testLogger(),
	)

	if len(allow) != 1 {
		t.Fatalf("allow entries = %+v, want the duplicate dropped", allow)
	}

	if allow[0].Prio != policy.RulePriority(0) {
		t.Fatalf("allow prio = %d, want %d (the first rule must win)",
			allow[0].Prio, policy.RulePriority(0))
	}
}

// TestCollectIPRulesPortless covers the any-port form: a cidr rule with
// no ports becomes the port=0 wildcard the datapath probes for.
func TestCollectIPRulesPortless(t *testing.T) {
	_, allow := collectIPRules(
		ipRulePolicy("block", cidrRule("192.0.2.10", policy.ActionAllow)),
		testLogger(),
	)

	if len(allow) != 1 {
		t.Fatalf("allow entries = %+v, want exactly one", allow)
	}

	if allow[0].Key.Port != 0 {
		t.Fatalf("portless rule got port %d, want the 0 wildcard", allow[0].Key.Port)
	}
}

// TestCollectIPRulesSingleHostPrefixes guards the parsing bug that made
// every IgnoreAnomaly-authored rule inert: those patterns carry a /32
// suffix, which net.ParseIP rejects outright.
func TestCollectIPRulesSingleHostPrefixes(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "bare address", pattern: "10.0.0.1", want: true},
		{name: "ipv4 single host", pattern: "10.0.0.1/32", want: true},
		{name: "ipv6 single host", pattern: "2001:db8::1/128", want: true},
		{name: "multi host prefix rejected", pattern: "10.0.0.0/24", want: false},
		{name: "unparseable rejected", pattern: "not-an-ip", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, allow := collectIPRules(
				ipRulePolicy("block", cidrRule(tc.pattern, policy.ActionAllow, 443)),
				testLogger(),
			)

			if got := len(allow) == 1; got != tc.want {
				t.Fatalf("pattern %q installed = %v, want %v (entries %+v)", tc.pattern, got, tc.want, allow)
			}
		})
	}
}

// TestCollectIPRulesDenyIPsFallback pins the CE/EE split: the standalone
// deny_ips blocklist has no position in any rule list, so it installs at
// SystemRulePriority — but only where a rule hasn't already claimed the
// key, otherwise the EE server's duplicate of a cidr deny rule would
// overwrite that rule's real position.
func TestCollectIPRulesDenyIPsFallback(t *testing.T) {
	pol := ipRulePolicy("block", cidrRule("10.0.0.1", policy.ActionDeny, 443))
	pol.DenyIPs = []policy.DenyIP{
		{IP: "10.0.0.1", Port: 443}, // already covered by the rule above
		{IP: "10.0.0.2", Port: 443}, // standalone — CE-style blocklist entry
	}
	pol.BuildLookups()

	deny, _ := collectIPRules(pol, testLogger())

	if len(deny) != 2 {
		t.Fatalf("deny entries = %+v, want 2", deny)
	}

	byIP := make(map[string]uint32, len(deny))
	for _, e := range deny {
		byIP[e.Key.IP] = e.Prio
	}

	if got := byIP["10.0.0.1"]; got != policy.RulePriority(0) {
		t.Fatalf("rule-covered deny prio = %d, want %d (rule position must win)", got, policy.RulePriority(0))
	}

	if got := byIP["10.0.0.2"]; got != policy.SystemRulePriority {
		t.Fatalf("standalone deny prio = %d, want %d", got, policy.SystemRulePriority)
	}
}

// TestJoinerIPAllowReversedOnDetach mirrors the deny-side ownership
// test: a job's IP allowances must not outlive it into a sibling that
// shares the netns.
func TestJoinerIPAllowReversedOnDetach(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 4242},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	defer mgr.DetachAll()

	pol := ipRulePolicy("block", cidrRule("10.0.0.5/32", policy.ActionAllow, 22))

	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "creator00000"}, 100, pol)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	if !contains(fp.allowedHosts, "10.0.0.5:22") {
		t.Fatalf("expected static allow entry installed, got %v", fp.allowedHosts)
	}

	if got := fp.ipPrio["10.0.0.5:22"]; got != policy.RulePriority(0) {
		t.Fatalf("static allow prio = %d, want %d", got, policy.RulePriority(0))
	}

	mgr.Detach("creator00000")

	if contains(fp.allowedHosts, "10.0.0.5:22") {
		t.Fatalf("static allow leaked after detach: %v", fp.allowedHosts)
	}
}
