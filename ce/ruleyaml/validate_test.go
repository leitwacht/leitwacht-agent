package ruleyaml

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

func writeRules(t *testing.T, path, ruleBlock string) {
	t.Helper()

	body := "schema_version: 1\nscopes:\n  - name: default\n    default_action: block\n" + ruleBlock

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ruleYAML(pt, pattern, action, ports string) string {
	s := fmt.Sprintf("    rule_sets:\n      \"\":\n        - pattern: %q\n          pattern_type: %s\n          action: %s\n", pattern, pt, action)
	if ports != "" {
		s += "          ports: " + ports + "\n"
	}

	return s
}

func TestLoaderRejectsUnenforceableRules(t *testing.T) {
	cases := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"cidr /8", ruleYAML("cidr", "10.0.0.0/8", "block", ""), "/32"},
		{"cidr /24", ruleYAML("cidr", "192.168.1.0/24", "allow", ""), "/32"},
		{"cidr /31", ruleYAML("cidr", "192.168.1.0/31", "allow", ""), "/32"},
		{"cidr ipv6", ruleYAML("cidr", "fd00::/8", "block", ""), "IPv6"},
		{"cidr ipv6 /128", ruleYAML("cidr", "fd00::1/128", "block", ""), "IPv6"},
		{"ip ipv6", ruleYAML("ip", "2001:db8::1", "block", ""), "IPv6"},
		{"ip v4-mapped ipv6", ruleYAML("ip", "::ffff:192.0.2.1", "block", ""), "IPv6"},
		{"ip with prefix", ruleYAML("ip", "192.0.2.1/32", "block", ""), "cidr"},
		{"fqdn port 65979 (wraps to 443)", ruleYAML("domain", "example.com", "allow", "[65979]"), "out of range"},
		{"fqdn port 65536 (wraps to any)", ruleYAML("domain", "example.com", "allow", "[65536]"), "out of range"},
		{"fqdn port 0", ruleYAML("domain", "example.com", "allow", "[0]"), "out of range"},
		{"fqdn port negative", ruleYAML("domain", "example.com", "allow", "[-1]"), "out of range"},
		{"cidr port 65979", ruleYAML("cidr", "192.0.2.1/32", "allow", "[65979]"), "out of range"},
		{"cidr port 65536", ruleYAML("ip", "192.0.2.1", "allow", "[65536]"), "out of range"},
		{"cidr port negative", ruleYAML("ip", "192.0.2.1", "allow", "[-5]"), "out of range"},
		{"fqdn scheme", ruleYAML("domain", "https://example.com", "allow", "[443]"), "scheme"},
		{"fqdn port suffix", ruleYAML("domain", "example.com:443", "allow", "[443]"), "port"},
		{"fqdn path", ruleYAML("domain", "example.com/x", "allow", "[443]"), "bare hostname"},
		{"fqdn double trailing dot", ruleYAML("domain", "example.com..", "allow", "[443]"), "empty label"},
		{"fqdn only dot", ruleYAML("domain", ".", "allow", "[443]"), "required"},
		{"fqdn leading dot", ruleYAML("domain", ".example.com", "allow", "[443]"), "empty label"},
		{"fqdn ip literal default type", ruleYAML("", "192.0.2.1", "allow", "[443]"), "use pattern_type ip"},
		{"fqdn ip literal explicit domain", ruleYAML("domain", "192.0.2.1", "block", ""), "use pattern_type ip"},
		{"bare star", ruleYAML("wildcard", "*", "allow", "[443]"), "every name"},
		{"deny star mid-label", ruleYAML("wildcard", "a.*.example.com", "block", ""), "first label"},
		{"partial star label", ruleYAML("wildcard", "api*.example.com", "allow", "[443]"), "whole label"},
		{"double star", ruleYAML("wildcard", "**.example.com", "allow", "[443]"), "whole label"},
		{"bad char", ruleYAML("domain", "ex!ample.com", "allow", "[443]"), "invalid character"},
		{"non-ascii", ruleYAML("domain", "bücher.de", "allow", "[443]"), "xn--"},
		{"label too long", ruleYAML("domain", strings.Repeat("a", 64)+".com", "allow", "[443]"), "63"},
		{"name too long", ruleYAML("domain", strings.Repeat("a.", 130)+"com", "allow", "[443]"), "253"},
		{"deny_ip ipv6", "    deny_ips:\n      - ip: \"2001:db8::1\"\n", "IPv6"},
		{"deny_ip cidr", "    deny_ips:\n      - ip: \"10.0.0.0/8\"\n", "cidr"},
		{"deny_ip port 65979", "    deny_ips:\n      - ip: 192.0.2.1\n        port: 65979\n", "out of range"},
		{"deny_ip port 65536", "    deny_ips:\n      - ip: 192.0.2.1\n        port: 65536\n", "out of range"},
		{"deny_ip port negative", "    deny_ips:\n      - ip: 192.0.2.1\n        port: -1\n", "out of range"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.yaml")
			writeRules(t, path, tc.block)

			_, err := New(path, slog.Default())
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoaderAcceptsEnforceableRules(t *testing.T) {
	cases := []struct {
		name        string
		block       string
		wantPattern string
	}{
		{"cidr /32", ruleYAML("cidr", "192.0.2.1/32", "allow", ""), "192.0.2.1/32"},
		{"cidr /32 with any-port 0", ruleYAML("cidr", "192.0.2.1/32", "allow", "[0]"), "192.0.2.1/32"},
		{"ip", ruleYAML("ip", "192.0.2.1", "block", ""), "192.0.2.1/32"},
		{"fqdn max port", ruleYAML("domain", "example.com", "allow", "[1, 65535]"), "example.com"},
		{"fqdn trailing dot stripped", ruleYAML("domain", "Example.COM.", "allow", "[443]"), "example.com"},
		{"allow star mid-label", ruleYAML("wildcard", "a.*.example.com", "allow", "[443]"), "a.*.example.com"},
		{"deny leading star", ruleYAML("wildcard", "*.example.com", "block", ""), "*.example.com"},
		{"underscore", ruleYAML("domain", "_dmarc.example.com", "block", ""), "_dmarc.example.com"},
		{"fqdn deny ignores port 0", ruleYAML("domain", "example.com", "block", "[0]"), "example.com"},
		{"wildcard", ruleYAML("wildcard", "*.example.com", "allow", "[443]"), "*.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.yaml")
			writeRules(t, path, tc.block)

			l, err := New(path, slog.Default())
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			pol, ok, err := l.Resolve("default")
			if err != nil || !ok {
				t.Fatalf("resolve: ok=%v err=%v", ok, err)
			}

			rules := pol.RulesForJob("")
			if len(rules) != 1 || rules[0].Pattern != tc.wantPattern {
				t.Fatalf("rules = %+v, want single pattern %q", rules, tc.wantPattern)
			}

			if strings.Contains(tc.name, "cidr") && rules[0].PatternType != policy.PatternCIDR {
				t.Errorf("pattern type = %q, want cidr", rules[0].PatternType)
			}
		})
	}
}

func TestReloadKeepsPreviousSnapshotOnUnenforceableRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, ruleYAML("domain", "good.example.com", "allow", "[443]"))

	l, err := New(path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	writeRules(t, path, ruleYAML("cidr", "10.0.0.0/8", "allow", ""))

	err = l.reload()
	if err == nil || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("reload err = %v, want error naming the rule", err)
	}

	pol, ok, _ := l.Resolve("default")
	if !ok {
		t.Fatal("previous snapshot lost after failed reload")
	}

	rules := pol.RulesForJob("")
	if len(rules) != 1 || rules[0].Pattern != "good.example.com" {
		t.Fatalf("rules after failed reload = %+v, want previous good rule", rules)
	}

	if !l.Ready() {
		t.Error("loader no longer ready after failed reload")
	}

}
