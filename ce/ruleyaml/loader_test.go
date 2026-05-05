package ruleyaml

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

func TestLoaderResolvesScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	yaml := `schema_version: 1
scopes:
  - name: default
    default_action: allow
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]
        - pattern: "*.amazonaws.com"
          pattern_type: wildcard
          action: allow
          ports: [443]
        - pattern: "10.0.0.0/8"
          pattern_type: cidr
          action: block
  - name: example/proj
    default_action: block
    rule_sets:
      "":
        - pattern: registry.gitlab.com
          pattern_type: domain
          action: allow
          ports: [443]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := New(path, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !l.Ready() {
		t.Fatal("loader not ready after successful parse")
	}

	pol, ok, err := l.Resolve("example/proj")
	if err != nil || !ok {
		t.Fatalf("resolve example/proj: ok=%v err=%v", ok, err)
	}
	if pol.Action != ActionBlock {
		t.Errorf("example/proj action = %q, want block", pol.Action)
	}

	pol, ok, _ = l.Resolve("does/not/exist")
	if !ok {
		t.Fatal("resolve fell through past default scope")
	}
	if pol.ProjectPath != "does/not/exist" {
		t.Errorf("default scope clone: ProjectPath = %q, want %q",
			pol.ProjectPath, "does/not/exist")
	}

	rules := pol.RulesForJob("")
	if len(rules) != 3 {
		t.Fatalf("default rules: got %d, want 3", len(rules))
	}
	if rules[2].PatternType != policy.PatternCIDR {
		t.Errorf("rule[2] pattern_type = %q, want cidr", rules[2].PatternType)
	}
	if rules[2].Action != policy.ActionDeny {
		t.Errorf("rule[2] action = %q, want deny", rules[2].Action)
	}
}

func TestLoaderRejectsBadSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	cases := map[string]string{
		"missing schema_version": `scopes: []`,
		"unknown action": `schema_version: 1
scopes:
  - name: default
    default_action: maybe
    rule_sets: {}`,
		"empty pattern": `schema_version: 1
scopes:
  - name: default
    default_action: allow
    rule_sets:
      "":
        - pattern: ""
          pattern_type: domain
          action: allow
          ports: [443]`,
		"allow+domain without ports": `schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow`,
		"bad cidr": `schema_version: 1
scopes:
  - name: default
    default_action: allow
    rule_sets:
      "":
        - pattern: "not-a-cidr"
          pattern_type: cidr
          action: block`,
		"per-rule audit rejected": `schema_version: 1
scopes:
  - name: default
    default_action: allow
    rule_sets:
      "":
        - pattern: example.com
          pattern_type: domain
          action: audit`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(path, slog.Default()); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
