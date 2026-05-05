package ruleyaml

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHotReloadAppliesNewRules writes a rules file, starts the loader's
// watcher, rewrites the file, and verifies Resolve returns the updated
// policy. This is the canonical CE feature — the daemon is supposed to
// pick up rule changes without a restart.
func TestHotReloadAppliesNewRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	v1 := `schema_version: 1
scopes:
  - name: default
    default_action: allow
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]
`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := New(path, slog.Default())
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	stop := make(chan struct{})
	defer close(stop)

	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() { runErr <- l.RunWithReady(stop, ready) }()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("loader never signalled ready")
	}

	// v1 → default_action allow.
	pol, ok, _ := l.Resolve("anything")
	if !ok || pol.Action != ActionAllow {
		t.Fatalf("v1: action=%q ok=%v", pol.Action, ok)
	}
	if v := l.Version(); v != 1 {
		t.Fatalf("v1: version = %d, want 1", v)
	}

	v2 := `schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]
`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait up to 3s for the loader to apply v2 (fsnotify + 250ms debounce).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pol, _, _ := l.Resolve("anything")
		if pol != nil && pol.Action == ActionBlock {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	pol, _, _ = l.Resolve("anything")
	if pol == nil || pol.Action != ActionBlock {
		t.Fatalf("v2 not applied within deadline; action=%q", pol.Action)
	}
	if v := l.Version(); v < 2 {
		t.Fatalf("v2: version = %d, want >= 2", v)
	}
}

// TestHotReloadKeepsPreviousOnBadYAML verifies that a malformed write
// to the rules file does not wipe the in-memory snapshot — the daemon
// keeps serving the last known good rules and logs a warning instead.
func TestHotReloadKeepsPreviousOnBadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	good := `schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: github.com
          pattern_type: domain
          action: allow
          ports: [443]
`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := New(path, slog.Default())
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() { _ = l.Run(stop) }()

	bad := `schema_version: 1
scopes:
  - name: default
    default_action: maybe-this-time
    rule_sets:
      "":
`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}

	// Give the watcher a chance to fire and fail.
	time.Sleep(750 * time.Millisecond)

	pol, ok, _ := l.Resolve("anything")
	if !ok || pol.Action != ActionBlock {
		t.Fatalf("bad reload wiped policy: action=%q ok=%v", pol.Action, ok)
	}
}
