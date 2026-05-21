package enforcer

import (
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

const (
	actionDNSBlocked = "dns_blocked"
	actionDNSDenied  = "dns_denied"
	testEvilDomain   = "evil.com"
)

// testDNSConfig builds a DNSProxyConfig + ResolvedPolicy with a
// pre-composed ordered rule list (empty job_name → applies to every
// query). Tests pass rules in the order the server would compose them
// (specific-first).
func testDNSConfig(action string, rules []policy.Rule) (*DNSProxyConfig, *policy.ResolvedPolicy, *ViolationRecorder) {
	rec := NewViolationRecorder(nil)

	pol := &policy.ResolvedPolicy{
		Action:   action,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": rules},
	}

	cfg := &DNSProxyConfig{
		Policy:         pol,
		Upstreams:      []string{"1.1.1.1:53"},
		LookupRecorder: func(_ uint64) *ViolationRecorder { return rec },
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		AddToAllowMap:  func(_ net.IP, _ []int) error { return nil },
	}

	return cfg, pol, rec
}

func allowFQDN(pattern string, ports ...int) policy.Rule {
	return policy.Rule{
		Pattern:     pattern,
		PatternType: policy.PatternFQDN,
		Action:      policy.ActionAllow,
		Ports:       ports,
	}
}

func denyFQDN(pattern, resolution string) policy.Rule {
	return policy.Rule{
		Pattern:     pattern,
		PatternType: policy.PatternFQDN,
		Action:      policy.ActionDeny,
		Resolution:  resolution,
	}
}

func makeQuery(domain string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.Id = dns.Id()

	return msg
}

func TestHandleDNSQuery_BlockedDomain(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{allowFQDN("pypi.org", 443)})

	msg := makeQuery(testEvilDomain, dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	assertSinkholeA(t, resp)

	violations, activity := rec.Snapshot()
	if len(violations) != 0 {
		t.Fatalf("dns block should not produce violations, got %+v", violations)
	}

	if len(activity) != 1 || activity[0].Domain != testEvilDomain || activity[0].Action != actionDNSBlocked {
		t.Fatalf("activity = %+v", activity)
	}

	if !containsIP(activity[0].ResolvedIPs, SinkholeIPv4) {
		t.Errorf("expected sinkhole IP in ResolvedIPs, got %v", activity[0].ResolvedIPs)
	}
}

func assertSinkholeA(t *testing.T, resp *dns.Msg) {
	t.Helper()

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR (sinkhole)", resp.Rcode)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(resp.Answer))
	}

	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}

	if a.A.String() != SinkholeIPv4 {
		t.Fatalf("sinkhole ip = %s, want %s", a.A, SinkholeIPv4)
	}
}

func containsIP(ips []string, target string) bool {
	for _, ip := range ips {
		if ip == target {
			return true
		}
	}

	return false
}

// TestHandleDNSQuery_LeitwachtAttached pins the attachment-liveness
// contract relied on by the leitwacht-init init container. Breaking any
// of these assertions silently disables the init container's exit
// condition for every CI job pod — they all time out.
//
//nolint:gocognit,cyclop // subtest closures inflate the metrics without real complexity
func TestHandleDNSQuery_LeitwachtAttached(t *testing.T) {
	const testVersion = "1.99.0"

	// Load a deny-all rule to prove the attachment short-circuit bypasses
	// policy matching — otherwise the attachment-liveness query would be denied.
	denyAll := denyFQDN("*", "")

	cfg, pol, rec := testDNSConfig("block", []policy.Rule{denyAll})
	cfg.AgentVersion = testVersion

	t.Run("A record returns pinned attachment IP", func(t *testing.T) {
		msg := makeQuery(ReservedDomains[0], dns.TypeA)
		resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
		}

		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d, want 1", len(resp.Answer))
		}

		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
		}

		if a.A.String() != attachedIPv4 {
			t.Fatalf("attachment ip = %s, want %s", a.A, attachedIPv4)
		}

		if a.Hdr.Ttl > attachedTTL {
			t.Fatalf("TTL = %d, want ≤ %d", a.Hdr.Ttl, attachedTTL)
		}
	})

	t.Run("TXT record echoes agent version", func(t *testing.T) {
		msg := makeQuery(ReservedDomains[0], dns.TypeTXT)
		resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
		}

		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d, want 1", len(resp.Answer))
		}

		txt, ok := resp.Answer[0].(*dns.TXT)
		if !ok {
			t.Fatalf("answer type = %T, want *dns.TXT", resp.Answer[0])
		}

		if len(txt.Txt) != 1 {
			t.Fatalf("txt strings = %d, want 1", len(txt.Txt))
		}

		want := "attached version=" + testVersion
		if txt.Txt[0] != want {
			t.Errorf("txt = %q, want %q", txt.Txt[0], want)
		}
	})

	t.Run("AAAA returns NOERROR with empty answer", func(t *testing.T) {
		msg := makeQuery(ReservedDomains[0], dns.TypeAAAA)
		resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR (not NXDOMAIN)", resp.Rcode)
		}

		if len(resp.Answer) != 0 {
			t.Errorf("answer count = %d, want 0", len(resp.Answer))
		}
	})

	t.Run("attachment-liveness query is not recorded", func(t *testing.T) {
		// Reset recorder by rebuilding the config.
		cfg, pol, rec := testDNSConfig("block", []policy.Rule{denyAll})
		cfg.AgentVersion = testVersion

		msg := makeQuery(ReservedDomains[0], dns.TypeA)
		_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

		_, activity := rec.Snapshot()
		for _, a := range activity {
			if a.Domain == ReservedDomains[0] {
				t.Errorf("attachment-liveness query should not hit the recorder: %+v", a)
			}
		}
	})

	t.Run("search-path expansion is suppressed", func(t *testing.T) {
		// K8s pod resolvers default to ndots:5; a query for the bare
		// _leitwacht.attached.local first walks search-list expansions.
		// Each variant must short-circuit to NXDOMAIN with no rule
		// match and no recording — otherwise the deny-all rule sinkholes
		// each expansion and bombs operators with bogus "DNS-blocked"
		// anomalies for names the init never meant to look up.
		cfg, pol, rec := testDNSConfig("block", []policy.Rule{denyAll})
		cfg.AgentVersion = testVersion

		variants := []string{
			"_leitwacht.attached.local.gitlab-runner.svc.cluster.local",
			"_leitwacht.attached.local.svc.cluster.local",
			"_leitwacht.attached.local.cluster.local",
		}

		for _, name := range variants {
			msg := makeQuery(name, dns.TypeA)
			resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

			if resp.Rcode != dns.RcodeNameError {
				t.Errorf("variant %q: rcode = %d, want NXDOMAIN", name, resp.Rcode)
			}

			if len(resp.Answer) != 0 {
				t.Errorf("variant %q: answer count = %d, want 0", name, len(resp.Answer))
			}
		}

		_, activity := rec.Snapshot()
		for _, a := range activity {
			for _, name := range variants {
				if strings.EqualFold(a.Domain, name) {
					t.Errorf("search-suffix variant should not be recorded: %+v", a)
				}
			}
		}
	})

	t.Run("empty agent version renders as 'unknown'", func(t *testing.T) {
		cfg, pol, rec := testDNSConfig("block", nil)
		cfg.AgentVersion = ""

		msg := makeQuery(ReservedDomains[0], dns.TypeTXT)
		resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

		txt, ok := resp.Answer[0].(*dns.TXT)
		if !ok {
			t.Fatalf("answer type = %T, want *dns.TXT", resp.Answer[0])
		}

		if txt.Txt[0] != "attached version=unknown" {
			t.Errorf("txt = %q, want 'attached version=unknown'", txt.Txt[0])
		}
	})
}

func TestHandleDNSQuery_EmptyQuestion(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", nil)

	msg := &dns.Msg{}
	msg.Id = dns.Id()
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %d, want REFUSED", resp.Rcode)
	}
}

func TestHandleDNSQuery_AllowedDomainForwarded(t *testing.T) {
	var addedIPs []string

	cfg, pol, rec := testDNSConfig("block", []policy.Rule{allowFQDN("example.com", 443)})
	cfg.AddToAllowMap = func(ip net.IP, _ []int) error {
		addedIPs = append(addedIPs, ip.String())

		return nil
	}

	msg := makeQuery("example.com", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	// Response depends on live DNS resolution (may fail in CI).
	if resp.Rcode == dns.RcodeNameError {
		t.Fatal("allowed domain should not return NXDOMAIN")
	}
}

func TestHandleDNSQuery_AuditModeForwardsEverything(t *testing.T) {
	cfg, pol, rec := testDNSConfig("audit", []policy.Rule{allowFQDN("pypi.org", 443)})

	msg := makeQuery(testEvilDomain, dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	violations, activity := rec.Snapshot()
	if len(violations) != 0 {
		t.Fatalf("audit mode should not produce violations, got %+v", violations)
	}

	for _, a := range activity {
		if a.Action == actionDNSBlocked {
			t.Fatal("audit mode should not block")
		}
	}
}

func TestHandleDNSQuery_WildcardAllowSingleLabel(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{allowFQDN("*.example.com", 443)})

	msg := makeQuery("sub.example.com", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	if resp.Rcode == dns.RcodeNameError {
		t.Fatal("wildcard-matched domain should not return NXDOMAIN")
	}
}

func TestHandleDNSQuery_WildcardAllowRejectsMultiLabel(t *testing.T) {
	// Allow wildcards use single-label semantics. *.example.com must NOT
	// match a.b.example.com — this is the Cilium-style security default.
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{allowFQDN("*.example.com", 443)})

	msg := makeQuery("a.b.example.com", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	assertSinkholeA(t, resp)

	_, activity := rec.Snapshot()
	if len(activity) != 1 || activity[0].Action != actionDNSBlocked {
		t.Fatalf("activity = %+v", activity)
	}
}

func TestHandleDNSQuery_ClusterLocalBlocked(t *testing.T) {
	// No rules at all — block-mode default sinkholes unknown queries.
	cfg, pol, rec := testDNSConfig("block", nil)

	msg := makeQuery("storage.googleapis.com.svc.cluster.local", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	assertSinkholeA(t, resp)

	violations, activity := rec.Snapshot()
	if len(violations) != 0 {
		t.Fatalf("violations = %d, want 0", len(violations))
	}

	if len(activity) != 1 || activity[0].Action != actionDNSBlocked {
		t.Fatalf("want 1 dns_blocked activity, got %+v", activity)
	}
}

func TestHandleDNSQuery_ClusterLocalAllowlisted(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		allowFQDN("my-api.staging.svc.cluster.local", 443),
	})

	msg := makeQuery("my-api.staging.svc.cluster.local", dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	_, activity := rec.Snapshot()
	if len(activity) != 1 || activity[0].Domain != "my-api.staging.svc.cluster.local" {
		t.Fatalf("allowlisted cluster.local should be forwarded and recorded, got activity=%+v", activity)
	}

	if activity[0].Action != "dns_allowed" {
		t.Fatalf("action = %q, want dns_allowed", activity[0].Action)
	}
}

func TestHandleDNSQuery_DenyRuleSinkhole(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		denyFQDN("telemetry.example.com", policy.DenyResolutionSinkhole),
		allowFQDN("pypi.org", 443),
	})

	msg := makeQuery("telemetry.example.com", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	assertSinkholeA(t, resp)

	violations, activity := rec.Snapshot()
	if len(violations) != 0 {
		t.Fatalf("deny rule should not produce violations, got %d", len(violations))
	}

	if len(activity) != 1 || activity[0].Domain != "telemetry.example.com" || activity[0].Action != actionDNSDenied {
		t.Fatalf("activity = %+v", activity)
	}
}

// First-match-wins: an earlier allow for exact foo beats a later deny wildcard.
func TestHandleDNSQuery_FirstMatch_AllowBeforeDenyWildcard(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		allowFQDN("foo.example.com", 443),
		denyFQDN("*.example.com", policy.DenyResolutionSinkhole),
	})

	msg := makeQuery("foo.example.com", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	if resp.Rcode == dns.RcodeNameError {
		t.Fatal("allow-first should forward foo.example.com, not NXDOMAIN")
	}

	_, activity := rec.Snapshot()
	if len(activity) != 1 || activity[0].Action != "dns_allowed" {
		t.Fatalf("expected dns_allowed activity, got %+v", activity)
	}
}

// First-match-wins: an earlier deny for exact evil beats a later allow wildcard.
func TestHandleDNSQuery_FirstMatch_DenyBeforeAllowWildcard(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		denyFQDN("evil.example.com", policy.DenyResolutionSinkhole),
		allowFQDN("*.example.com", 443),
	})

	msg := makeQuery("evil.example.com", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	assertSinkholeA(t, resp)

	_, activity := rec.Snapshot()
	if len(activity) != 1 || activity[0].Action != actionDNSDenied {
		t.Fatalf("expected dns_denied activity, got %+v", activity)
	}
}

// "Block cluster except kube-dns" — the scenario `HANDOFF.md` called out
// as unsupported under deny-first. With ordered rules, the operator puts
// the allow exact before the deny wildcard.
func TestHandleDNSQuery_BlockClusterExceptKubeDNS(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		allowFQDN("kube-dns.kube-system.svc.cluster.local", 53),
		denyFQDN("*.svc.cluster.local", policy.DenyResolutionNXDomain),
		denyFQDN("*.cluster.local", policy.DenyResolutionNXDomain),
	})

	// Allowed kube-dns forwards.
	_ = HandleDNSQuery(
		makeQuery("kube-dns.kube-system.svc.cluster.local", dns.TypeA),
		cfg, pol, rec, 0, "", "", "", 0,
	)

	// Any other cluster.local returns NXDOMAIN.
	resp := HandleDNSQuery(
		makeQuery("other.svc.cluster.local", dns.TypeA),
		cfg, pol, rec, 0, "", "", "", 0,
	)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("other.svc.cluster.local rcode = %d, want NXDOMAIN", resp.Rcode)
	}

	// k8s search-path variant also NXDOMAINs (suffix-match on the deny).
	resp = HandleDNSQuery(
		makeQuery("git.example.com.gitlab-runner.svc.cluster.local", dns.TypeA),
		cfg, pol, rec, 0, "", "", "", 0,
	)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("search-path rcode = %d, want NXDOMAIN", resp.Rcode)
	}
}

// Wildcard deny with nxdomain resolution — regression guard for a
// past cluster.local outage where service-VIP queries leaked past
// a wildcard deny rule.
func TestHandleDNSQuery_ClusterLocalNXDomain(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		denyFQDN("*.svc.cluster.local", policy.DenyResolutionNXDomain),
	})

	msg := makeQuery("git.example.com.gitlab-runner.svc.cluster.local", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN (%d)", resp.Rcode, dns.RcodeNameError)
	}

	if len(resp.Answer) != 0 {
		t.Errorf("nxdomain response should have empty answer, got %d RRs", len(resp.Answer))
	}

	_, activity := rec.Snapshot()
	if len(activity) != 1 {
		t.Fatalf("expected 1 dns_activity entry, got %d", len(activity))
	}

	if activity[0].Action != actionDNSDenied {
		t.Errorf("action = %q, want dns_denied", activity[0].Action)
	}

	if len(activity[0].ResolvedIPs) != 0 {
		t.Errorf("nxdomain deny should not record ResolvedIPs, got %v", activity[0].ResolvedIPs)
	}
}

func TestHandleDNSQuery_ClusterLocalSinkhole(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		denyFQDN("*.attacker.net", policy.DenyResolutionSinkhole),
	})

	msg := makeQuery("c2.beacon.attacker.net", dns.TypeA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	assertSinkholeA(t, resp)

	_, activity := rec.Snapshot()
	if len(activity) != 1 {
		t.Fatalf("expected 1 dns_activity entry, got %d", len(activity))
	}

	if activity[0].Action != actionDNSDenied {
		t.Errorf("action = %q, want dns_denied", activity[0].Action)
	}

	if len(activity[0].ResolvedIPs) != 1 || activity[0].ResolvedIPs[0] != SinkholeIPv4 {
		t.Errorf("sinkhole deny should record ResolvedIPs=[%s], got %v", SinkholeIPv4, activity[0].ResolvedIPs)
	}
}

func TestHandleDNSQuery_BlockedAAAAFallsBackToNXDOMAIN(t *testing.T) {
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{allowFQDN("pypi.org", 443)})

	msg := makeQuery(testEvilDomain, dns.TypeAAAA)
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("AAAA blocked query should NXDOMAIN, got rcode=%d", resp.Rcode)
	}

	_, activity := rec.Snapshot()
	if len(activity) != 1 || activity[0].Action != actionDNSBlocked {
		t.Fatalf("activity = %+v", activity)
	}

	if len(activity[0].ResolvedIPs) != 0 {
		t.Errorf("AAAA block should not record sinkhole IP, got %v", activity[0].ResolvedIPs)
	}
}

func TestDNSProxy_UpdatePolicy(t *testing.T) {
	// Start with audit-all empty policy.
	auditPol := &policy.ResolvedPolicy{
		Action:   "audit",
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": nil},
	}
	rec := NewViolationRecorder(nil)
	cfg := &DNSProxyConfig{
		Policy:         auditPol,
		Upstreams:      []string{"1.1.1.1:53"},
		LookupRecorder: func(_ uint64) *ViolationRecorder { return rec },
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		AddToAllowMap:  func(_ net.IP, _ []int) error { return nil },
	}

	proxy := NewDNSProxy(cfg)

	msg := makeQuery(testEvilDomain, dns.TypeA)
	pol := proxy.policy.Load()
	resp := HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", 0)

	if resp.Rcode == dns.RcodeNameError {
		t.Fatal("audit-all mode should not return NXDOMAIN")
	}

	violations, _ := rec.Snapshot()
	if len(violations) != 0 {
		t.Fatalf("audit-all mode should not produce violations, got %+v", violations)
	}

	// Swap to a block policy that only allows pypi.org.
	blockPol := &policy.ResolvedPolicy{
		Action:   "block",
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": {allowFQDN("pypi.org", 443)}},
	}
	proxy.UpdatePolicy(blockPol)

	rec2 := NewViolationRecorder(nil)
	msg2 := makeQuery(testEvilDomain, dns.TypeA)
	pol2 := proxy.policy.Load()
	resp2 := HandleDNSQuery(msg2, cfg, pol2, rec2, 0, "", "", "", 0)
	assertSinkholeA(t, resp2)

	violations2, activity2 := rec2.Snapshot()
	if len(violations2) != 0 {
		t.Fatalf("dns block should not produce violations, got %+v", violations2)
	}

	if len(activity2) != 1 || activity2[0].Action != actionDNSBlocked {
		t.Fatalf("expected dns_blocked activity after swap, got %+v", activity2)
	}
}

func TestHandleDNSQuery_OnDNSViolation_BlockMode(t *testing.T) {
	// Verify OnDNSViolation fires for both dns_blocked and dns_denied
	// in block mode, with the correct domain and action.
	cfg, pol, rec := testDNSConfig("block", []policy.Rule{
		denyFQDN("denied.example.com", policy.DenyResolutionSinkhole),
		allowFQDN("allowed.example.com", 443),
	})

	var violations []struct {
		cgroupID uint64
		domain   string
		action   string
	}

	cfg.OnDNSViolation = func(cgroupID uint64, domain, action string) {
		violations = append(violations, struct {
			cgroupID uint64
			domain   string
			action   string
		}{cgroupID: cgroupID, domain: domain, action: action})
	}

	const testCgroupID uint64 = 42

	// Case 1: default-allow sinkhole (dns_blocked) -- no rule matches, block mode
	msg := makeQuery(testEvilDomain, dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", testCgroupID)

	if len(violations) != 1 {
		t.Fatalf("expected 1 OnDNSViolation call for dns_blocked, got %d", len(violations))
	}

	if violations[0].domain != testEvilDomain {
		t.Errorf("domain = %q, want %q", violations[0].domain, testEvilDomain)
	}

	if violations[0].action != actionDNSBlocked {
		t.Errorf("action = %q, want %q", violations[0].action, actionDNSBlocked)
	}

	if violations[0].cgroupID != testCgroupID {
		t.Errorf("cgroupID = %d, want %d", violations[0].cgroupID, testCgroupID)
	}

	// Case 2: explicit deny rule (dns_denied)
	violations = nil

	msg = makeQuery("denied.example.com", dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", testCgroupID)

	if len(violations) != 1 {
		t.Fatalf("expected 1 OnDNSViolation call for dns_denied, got %d", len(violations))
	}

	if violations[0].domain != "denied.example.com" {
		t.Errorf("domain = %q, want %q", violations[0].domain, "denied.example.com")
	}

	if violations[0].action != actionDNSDenied {
		t.Errorf("action = %q, want %q", violations[0].action, actionDNSDenied)
	}

	// Case 3: allowed domain -- no violation callback
	violations = nil

	msg = makeQuery("allowed.example.com", dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", testCgroupID)

	if len(violations) != 0 {
		t.Fatalf("allowed domain should not trigger OnDNSViolation, got %d calls", len(violations))
	}

	_ = rec // suppress unused warning
}

func TestHandleDNSQuery_OnDNSViolation_AuditMode(t *testing.T) {
	// Verify OnDNSViolation is NOT called in audit mode --
	// audit mode records but does not kill.
	cfg, pol, rec := testDNSConfig("audit", []policy.Rule{
		denyFQDN("denied.example.com", policy.DenyResolutionSinkhole),
	})

	var violationCalled bool

	cfg.OnDNSViolation = func(_ uint64, _, _ string) {
		violationCalled = true
	}

	const testCgroupID uint64 = 42

	// Case 1: default-allow in audit mode -- forwarded, no kill
	msg := makeQuery(testEvilDomain, dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", testCgroupID)

	if violationCalled {
		t.Fatal("OnDNSViolation should not be called in audit mode (default-allow)")
	}

	// Case 2: explicit deny rule in audit mode -- forwarded, no kill
	msg = makeQuery("denied.example.com", dns.TypeA)
	_ = HandleDNSQuery(msg, cfg, pol, rec, 0, "", "", "", testCgroupID)

	if violationCalled {
		t.Fatal("OnDNSViolation should not be called in audit mode (deny rule)")
	}

	_ = rec // suppress unused warning
}
