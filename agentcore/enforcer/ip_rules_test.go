package enforcer

import (
	"context"
	"errors"
	"net"
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
		// IPv6 is refused rather than installed: PackAllowKey has no
		// 4-byte form for it and would write an all-zero (0.0.0.0) key,
		// producing a rule that reads as enforced and isn't.
		{name: "ipv6 single host rejected", pattern: "2001:db8::1/128", want: false},
		{name: "bare ipv6 rejected", pattern: "2001:db8::1", want: false},
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

// TestJoinerIPRulesReversedOnFailedAttach covers the leak path: attach
// installs IP rules before attaching the enforcer, and a failure there
// removes the container from m.enforcers — so Detach returns early and
// never reverses them. On the joiner path the netns outlives the
// failure, which would leave a never-enforced container's *allow* rules
// live for its siblings.
func TestJoinerIPRulesReversedOnFailedAttach(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath:      "/sys/fs/cgroup/test",
		netnsByPID:      map[int]uint64{100: 4242},
		attachCgroupErr: errors.New("synthetic attach failure"),
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	defer mgr.DetachAll()

	pol := ipRulePolicy("block", cidrRule("10.0.0.9/32", policy.ActionAllow, 443))

	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "failed000000"}, 100, pol)
	if err == nil {
		t.Fatal("expected attach to fail")
	}

	if contains(fp.allowedHosts, "10.0.0.9:443") {
		t.Fatalf("allow entry survived a failed attach: %v", fp.allowedHosts)
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

// sharedNetnsManager returns a manager whose pids 100 and 101 share one
// netns, so two Attach calls exercise the joiner path.
func sharedNetnsManager(t *testing.T) (*Manager, *fakePlatform) {
	t.Helper()

	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 4242, 101: 4242},
	}

	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	t.Cleanup(func() { mgr.DetachAll() })

	return mgr, fp
}

// TestSharedDenySurvivesSiblingDetach: two containers in one netns with
// the same cidr deny share one map key. The first to detach must not
// delete it for the other (that would fail open for the survivor).
func TestSharedDenySurvivesSiblingDetach(t *testing.T) {
	mgr, fp := sharedNetnsManager(t)
	ctx := context.Background()
	pol := ipRulePolicy("block", cidrRule("10.0.0.7/32", policy.ActionDeny, 443),
		cidrRule("10.0.0.8/32", policy.ActionAllow, 22))

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "build0000000"}, 100, pol); err != nil {
		t.Fatalf("attach build: %v", err)
	}

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "service00000"}, 101, pol); err != nil {
		t.Fatalf("attach service: %v", err)
	}

	mgr.Detach("build0000000")

	if !contains(fp.deniedIPs, "10.0.0.7:443") {
		t.Fatalf("deny removed while another container still owns it: %v", fp.deniedIPs)
	}

	if !contains(fp.allowedHosts, "10.0.0.8:22") {
		t.Fatalf("static allow removed while another container still owns it: %v", fp.allowedHosts)
	}

	mgr.Detach("service00000")

	if contains(fp.deniedIPs, "10.0.0.7:443") || contains(fp.allowedHosts, "10.0.0.8:22") {
		t.Fatalf("entries leaked after the last owner detached: deny=%v allow=%v", fp.deniedIPs, fp.allowedHosts)
	}
}

// TestSharedDenyPriorityResolvesToMin: owners with different priorities
// for one key install the minimum, and the departing owner of the
// minimum re-Puts the survivor's priority.
func TestSharedDenyPriorityResolvesToMin(t *testing.T) {
	mgr, fp := sharedNetnsManager(t)
	ctx := context.Background()

	// "late" lists the deny at index 1 (prio 2), "early" at index 0 (prio 1).
	late := ipRulePolicy("block",
		cidrRule("10.0.0.8/32", policy.ActionAllow, 22),
		cidrRule("10.0.0.7/32", policy.ActionDeny, 443))
	early := ipRulePolicy("block", cidrRule("10.0.0.7/32", policy.ActionDeny, 443))

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "late00000000"}, 100, late); err != nil {
		t.Fatalf("attach late: %v", err)
	}

	if got := fp.ipPrio["10.0.0.7:443"]; got != policy.RulePriority(1) {
		t.Fatalf("prio after first owner = %d, want %d", got, policy.RulePriority(1))
	}

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "early0000000"}, 101, early); err != nil {
		t.Fatalf("attach early: %v", err)
	}

	if got := fp.ipPrio["10.0.0.7:443"]; got != policy.RulePriority(0) {
		t.Fatalf("prio with both owners = %d, want min %d", got, policy.RulePriority(0))
	}

	// Detaching the better owner must raise the entry back to the
	// survivor's priority, not leave the departed container's behind.
	mgr.Detach("early0000000")

	if !contains(fp.deniedIPs, "10.0.0.7:443") {
		t.Fatalf("deny dropped while an owner remains: %v", fp.deniedIPs)
	}

	if got := fp.ipPrio["10.0.0.7:443"]; got != policy.RulePriority(1) {
		t.Fatalf("prio after better owner left = %d, want re-Put %d", got, policy.RulePriority(1))
	}

	// And the order of arrival must not matter: a worse later owner
	// leaves the better one in place.
	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "early0000000"}, 101, early); err != nil {
		t.Fatalf("re-attach early: %v", err)
	}

	mgr.Detach("late00000000")

	if got := fp.ipPrio["10.0.0.7:443"]; got != policy.RulePriority(0) {
		t.Fatalf("prio after worse owner left = %d, want %d", got, policy.RulePriority(0))
	}
}

// TestSinkholeNotDeletedByJoinerRule: a joiner rule naming the sinkhole
// key can neither lower its priority nor delete it on detach.
func TestSinkholeNotDeletedByJoinerRule(t *testing.T) {
	mgr, fp := sharedNetnsManager(t)
	ctx := context.Background()
	pol := ipRulePolicy("block", cidrRule(SinkholeIPv4, policy.ActionDeny))

	// keeper holds the netns open so detaching the joiner is not a teardown.
	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "keeper000000"}, 100, ipRulePolicy("block")); err != nil {
		t.Fatalf("attach keeper: %v", err)
	}

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "build0000000"}, 101, pol); err != nil {
		t.Fatalf("attach build: %v", err)
	}

	mgr.Detach("build0000000")

	if !contains(fp.deniedIPs, SinkholeIPv4+":0") {
		t.Fatalf("sinkhole deny removed by a joiner detach: %v", fp.deniedIPs)
	}

	if got := fp.ipPrio[SinkholeIPv4+":0"]; got != policy.SystemRulePriority {
		t.Fatalf("sinkhole prio = %d, want %d", got, policy.SystemRulePriority)
	}
}

// failDenyPlatform wraps the fake platform so deny Puts fail, to prove the
// block-mode fail-closed path.
type failDenyPlatform struct {
	*fakePlatform
}

func (f *failDenyPlatform) LoadEBPF(a bool, c []net.IPNet) (EBPFHandle, error) {
	h, err := f.fakePlatform.LoadEBPF(a, c)
	if err != nil {
		return nil, err
	}

	return &failDenyHandle{EBPFHandle: h}, nil
}

type failDenyHandle struct {
	EBPFHandle
}

func (h *failDenyHandle) AddDeniedIP(ip net.IP, port int, prio uint32) error {
	if ip.String() == "10.0.0.7" {
		return errors.New("synthetic map full")
	}

	return h.EBPFHandle.AddDeniedIP(ip, port, prio)
}

// TestDenyInstallFailureFailsBlockAttach: a deny that cannot be written
// is a permitted destination the operator asked to block. Block mode
// must refuse the attach; audit mode only observes and proceeds.
func TestDenyInstallFailureFailsBlockAttach(t *testing.T) {
	fp := &failDenyPlatform{&fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	defer mgr.DetachAll()

	deny := cidrRule("10.0.0.7/32", policy.ActionDeny, 443)

	_, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "block0000000"}, 100,
		ipRulePolicy("block", deny))
	if !errors.Is(err, ErrIPRuleInstall) {
		t.Fatalf("block-mode attach error = %v, want ErrIPRuleInstall", err)
	}

	if mgr.IsEnforced("block0000000") || mgr.Count() != 0 {
		t.Fatalf("failed attach left state behind: count=%d", mgr.Count())
	}

	e, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "audit0000000"}, 101,
		ipRulePolicy("audit", deny))
	if err != nil || e == nil {
		t.Fatalf("audit-mode attach = (%v, %v), want success", e, err)
	}
}

// TestStrictestMemberPolicyWins: a passive or audit joiner must not
// downgrade a pod whose build container is enforcing, and the mode must
// follow the strictest survivor when the enforcing member leaves.
func TestStrictestMemberPolicyWins(t *testing.T) {
	mgr, _ := sharedNetnsManager(t)
	ctx := context.Background()

	blockPol := ipRulePolicy("block", cidrRule("10.0.0.7/32", policy.ActionDeny))
	auditWithRules := ipRulePolicy("audit", cidrRule("10.0.0.9/32", policy.ActionDeny))
	passive := ipRulePolicy("audit")

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "build0000000"}, 100, blockPol); err != nil {
		t.Fatalf("attach build: %v", err)
	}

	mgr.mu.Lock()
	nctx := mgr.enforcers["build0000000"].ctx
	mgr.mu.Unlock()

	handle := nctx.ebpf.(*fakeEBPFHandle)

	if nctx.auditMode.Load() {
		t.Fatal("block creator should leave the netns in block mode")
	}

	// Passive (non-enrolled sentinel) joiner.
	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "helper000000"}, 101, passive); err != nil {
		t.Fatalf("attach passive: %v", err)
	}

	if nctx.auditMode.Load() || handle.modeUpdated {
		t.Fatalf("passive joiner downgraded an enforcing netns (audit=%v setMode=%v)",
			nctx.auditMode.Load(), handle.modeUpdated)
	}

	if got := nctx.dnsProxy.policy.Load(); got != blockPol {
		t.Fatalf("dns proxy policy was swapped to the passive joiner's: %+v", got)
	}

	// Audit joiner with rules is also weaker than block.
	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "svc000000000"}, 101, auditWithRules); err != nil {
		t.Fatalf("attach audit: %v", err)
	}

	if nctx.auditMode.Load() || nctx.dnsProxy.policy.Load() != blockPol {
		t.Fatal("audit joiner downgraded an enforcing netns")
	}

	// Enforcing member leaves: strictest survivor (audit with rules) takes over.
	mgr.Detach("build0000000")

	if !nctx.auditMode.Load() || !handle.auditMode {
		t.Fatal("netns stayed in block mode after the only enforcing member left")
	}

	if got := nctx.dnsProxy.policy.Load(); got != auditWithRules {
		t.Fatalf("dns proxy policy after detach = %+v, want the audit-with-rules member's", got)
	}
}

// TestPassiveSentinelExemptFromConcurrencyLimit: a non-enrolled project's
// passive attach enforces nothing and must neither be refused by, nor
// consume, the enforcement limit.
func TestPassiveSentinelExemptFromConcurrencyLimit(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 1, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	defer mgr.DetachAll()

	ctx := context.Background()
	passive := ipRulePolicy("audit")

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "passive000001"}, 10, passive); err != nil {
		t.Fatalf("passive attach: %v", err)
	}

	// The passive sentinel does not consume the single enforcement slot...
	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "enforced00001"}, 11, ipRulePolicy("block", cidrRule("10.0.0.1/32", policy.ActionDeny))); err != nil {
		t.Fatalf("enforcing attach refused because of a passive sentinel: %v", err)
	}

	// ...a second enforcing container is refused, a second sentinel is not.
	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "enforced00002"}, 12, ipRulePolicy("block", cidrRule("10.0.0.1/32", policy.ActionDeny))); !errors.Is(err, ErrMaxConcurrent) {
		t.Fatalf("err = %v, want ErrMaxConcurrent", err)
	}

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "passive000002"}, 13, passive); err != nil {
		t.Fatalf("second passive attach refused: %v", err)
	}

	mgr.Detach("passive000001")
	mgr.Detach("passive000002")
	mgr.Detach("enforced00001")

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "enforced00003"}, 14, ipRulePolicy("block", cidrRule("10.0.0.1/32", policy.ActionDeny))); err != nil {
		t.Fatalf("slot not released after detach: %v", err)
	}
}

// TestPolicyChangeFlushesDNSAllows: DNS-derived allows carry the priority
// of the policy in force when they were seeded; when a stricter member
// changes the effective policy they must be dropped.
func TestPolicyChangeFlushesDNSAllows(t *testing.T) {
	mgr, fp := sharedNetnsManager(t)
	ctx := context.Background()

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "helper000000"}, 100, ipRulePolicy("audit", cidrRule("10.0.0.9/32", policy.ActionAllow))); err != nil {
		t.Fatalf("attach helper: %v", err)
	}

	mgr.mu.Lock()
	h := mgr.enforcers["helper000000"].ctx.ebpf
	mgr.mu.Unlock()

	if err := h.AddAllowedIP(net.ParseIP("203.0.113.5"), []int{443}, 1); err != nil {
		t.Fatalf("seed allow: %v", err)
	}

	if _, err := mgr.Attach(ctx, ContainerInfo{ContainerID: "build0000000"}, 101, ipRulePolicy("block", cidrRule("10.0.0.7/32", policy.ActionDeny))); err != nil {
		t.Fatalf("attach build: %v", err)
	}

	if len(fp.allowedIPs) != 0 {
		t.Fatalf("dns allows survived a policy change: %v", fp.allowedIPs)
	}
}

// TestSinkholeSeedFailureFailsBlockCreator: without the sinkhole deny,
// blocked DNS answers point at an address the datapath doesn't drop.
func TestSinkholeSeedFailureFailsBlockCreator(t *testing.T) {
	fp := &sinkholeFailPlatform{&fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	defer mgr.DetachAll()

	if _, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "block0000000"}, 100, ipRulePolicy("block")); err == nil {
		t.Fatal("block-mode attach succeeded without a sinkhole deny")
	}

	if e, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "audit0000000"}, 101, ipRulePolicy("audit")); err != nil || e == nil {
		t.Fatalf("audit-mode attach = (%v, %v), want success", e, err)
	}
}

type sinkholeFailPlatform struct{ *fakePlatform }

func (f *sinkholeFailPlatform) LoadEBPF(a bool, c []net.IPNet) (EBPFHandle, error) {
	h, err := f.fakePlatform.LoadEBPF(a, c)
	if err != nil {
		return nil, err
	}

	return &sinkholeFailHandle{EBPFHandle: h}, nil
}

type sinkholeFailHandle struct{ EBPFHandle }

func (h *sinkholeFailHandle) AddDeniedIP(ip net.IP, port int, prio uint32) error {
	if ip.String() == SinkholeIPv4 {
		return errors.New("synthetic map full")
	}

	return h.EBPFHandle.AddDeniedIP(ip, port, prio)
}
