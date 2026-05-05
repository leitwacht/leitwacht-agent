package policy

import (
	"testing"
	"time"
)

const actionAudit = "audit"

func TestResolvedPolicy_BuildLookups_DenyIPs(t *testing.T) {
	p := &ResolvedPolicy{
		DenyIPs: []DenyIP{
			{IP: "10.0.0.1", Port: 443},
			{IP: "192.168.1.0/24", Port: 0},
		},
	}
	p.BuildLookups()

	if !p.DenyIPSet[DenyIPKey{IP: "10.0.0.1", Port: 443}] {
		t.Fatal("expected 10.0.0.1:443 in DenyIPSet")
	}
	if !p.DenyIPSet[DenyIPKey{IP: "192.168.1.0/24", Port: 0}] {
		t.Fatal("expected 192.168.1.0/24 in DenyIPSet")
	}
}

func TestResolvedPolicy_RulesForJob(t *testing.T) {
	p := &ResolvedPolicy{
		RuleSets: map[string][]Rule{
			"": {
				{Pattern: "base.example.com", PatternType: PatternFQDN, Action: ActionAllow},
			},
			"build": {
				{Pattern: "build.example.com", PatternType: PatternFQDN, Action: ActionAllow},
			},
		},
	}

	build := p.RulesForJob("build")
	if len(build) != 1 || build[0].Pattern != "build.example.com" {
		t.Fatalf("build rules = %+v", build)
	}

	unknown := p.RulesForJob("lint")
	if len(unknown) != 1 || unknown[0].Pattern != "base.example.com" {
		t.Fatalf("fallback rules = %+v", unknown)
	}

	empty := (&ResolvedPolicy{}).RulesForJob("anything")
	if empty != nil {
		t.Fatalf("nil-RuleSets should return nil, got %+v", empty)
	}
}

func TestResolvedPolicy_IsExpired(t *testing.T) {
	p := &ResolvedPolicy{
		FetchedAt: time.Now().Add(-10 * time.Minute),
		TTL:       5 * time.Minute,
	}
	if !p.IsExpired() {
		t.Fatal("expected expired")
	}

	p.FetchedAt = time.Now()
	if p.IsExpired() {
		t.Fatal("expected not expired")
	}
}

func TestResolvedPolicy_ForJob(t *testing.T) {
	p := &ResolvedPolicy{
		ProjectPath: "team/app",
		Action:      actionAudit,
		JobActions:  map[string]string{"deploy": "block"},
		RuleSets: map[string][]Rule{
			"": {{Pattern: "pypi.org", PatternType: PatternFQDN, Action: ActionAllow, Ports: []int{443}}},
			"test-backend": {
				{Pattern: "mock.api", PatternType: PatternFQDN, Action: ActionAllow, Ports: []int{8080}},
			},
		},
	}

	testPol := p.ForJob("test-backend")
	if testPol.Action != actionAudit {
		t.Fatalf("action = %q, want audit (inherited)", testPol.Action)
	}

	rules := testPol.RulesForJob("")
	if len(rules) != 1 || rules[0].Pattern != "mock.api" {
		t.Fatalf("test-backend rules = %+v", rules)
	}

	deployPol := p.ForJob("deploy")
	if deployPol.Action != "block" {
		t.Fatalf("deploy action = %q, want block", deployPol.Action)
	}
	deployRules := deployPol.RulesForJob("")
	if len(deployRules) != 1 || deployRules[0].Pattern != "pypi.org" {
		t.Fatalf("deploy fallback rules = %+v", deployRules)
	}

	if p.Action != actionAudit {
		t.Fatal("ForJob mutated original Action")
	}
}
