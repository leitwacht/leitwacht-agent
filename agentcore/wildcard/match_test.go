package wildcard

import "testing"

func TestMatchesFQDN(t *testing.T) {
	allowed := map[string]bool{
		"pypi.org":            true,
		"*.example.com":       true,
		"*.*.cdn.example.com": true,
		"registry.npmjs.org":  true,
	}

	tests := []struct {
		domain string
		want   bool
	}{
		// Exact matches
		{"pypi.org", true},
		{"registry.npmjs.org", true},
		{"PYPI.ORG", true},  // case insensitive
		{"pypi.org.", true}, // trailing dot

		// Wildcard: *.example.com (1 label)
		{"a.example.com", true},
		{"sub.example.com", true},
		{"example.com", false},     // 0 labels — no match
		{"a.b.example.com", false}, // 2 labels — no match

		// Wildcard: *.*.cdn.example.com (2 labels)
		{"x.y.cdn.example.com", true},
		{"a.b.cdn.example.com", true},
		{"z.cdn.example.com", false},     // only 1 label — no match
		{"a.b.c.cdn.example.com", false}, // 3 labels — no match

		// Not in allowlist
		{"evil.com", false},
		{"attacker.example.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := MatchesFQDN(tt.domain, allowed)
			if got != tt.want {
				t.Errorf("MatchesFQDN(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestPortsForFQDN(t *testing.T) {
	fqdnPorts := map[string]map[int]bool{
		"pypi.org":      {443: true},
		"*.example.com": {443: true, 80: true},
	}

	ports := PortsForFQDN("pypi.org", fqdnPorts)
	if !ports[443] {
		t.Fatal("expected port 443 for pypi.org")
	}

	ports = PortsForFQDN("sub.example.com", fqdnPorts)
	if !ports[80] {
		t.Fatal("expected port 80 for *.example.com wildcard")
	}

	ports = PortsForFQDN("evil.com", fqdnPorts)
	if ports != nil {
		t.Fatal("expected nil ports for unmatched domain")
	}
}

func TestParentDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"a.b.example.com", "b.example.com"},
		{"sub.example.com", "example.com"},
		{"example.com", "com"},
		{"localhost", ""},
		{"A.Example.COM.", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := ParentDomain(tt.domain)
			if got != tt.want {
				t.Errorf("ParentDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsWildcard(t *testing.T) {
	if !IsWildcard("*.example.com") {
		t.Error("expected *.example.com to be wildcard")
	}

	if IsWildcard("example.com") {
		t.Error("expected example.com to not be wildcard")
	}
}

// TestMatchesDeny verifies suffix-match semantics for deny wildcards. The
// critical case is k8s resolver search paths: `git.example.com.svc.
// cluster.local` must match `*.svc.cluster.local` even though it has
// multiple labels before the wildcard suffix. The allow-side matcher
// (MatchesFQDN) would reject this — deny rules deliberately differ.
func TestMatchesDeny(t *testing.T) {
	denySet := map[string]string{
		"*.svc.cluster.local": "nxdomain",
		"*.cluster.local":     "nxdomain",
		"blocked.example.com": "sinkhole",
		"*.attacker.net":      "sinkhole",
	}

	tests := []struct {
		name           string
		domain         string
		wantMatched    bool
		wantPattern    string
		wantResolution string
	}{
		{
			name:           "exact match returns sinkhole resolution",
			domain:         "blocked.example.com",
			wantMatched:    true,
			wantPattern:    "blocked.example.com",
			wantResolution: "sinkhole",
		},
		{
			name:           "single-label wildcard matches",
			domain:         "foo.svc.cluster.local",
			wantMatched:    true,
			wantPattern:    "*.svc.cluster.local",
			wantResolution: "nxdomain",
		},
		{
			name:           "multi-label wildcard suffix matches (k8s search path)",
			domain:         "git.example.com.gitlab-runner.svc.cluster.local",
			wantMatched:    true,
			wantPattern:    "*.svc.cluster.local",
			wantResolution: "nxdomain",
		},
		{
			name:           "deeper suffix also matches the broader pattern",
			domain:         "etcd.kube-system.svc.cluster.local",
			wantMatched:    true,
			wantPattern:    "*.svc.cluster.local",
			wantResolution: "nxdomain",
		},
		{
			name:           "case insensitive",
			domain:         "FOO.SVC.CLUSTER.LOCAL",
			wantMatched:    true,
			wantPattern:    "*.svc.cluster.local",
			wantResolution: "nxdomain",
		},
		{
			name:           "trailing dot stripped",
			domain:         "foo.svc.cluster.local.",
			wantMatched:    true,
			wantPattern:    "*.svc.cluster.local",
			wantResolution: "nxdomain",
		},
		{
			name:           "bare svc.cluster.local matches *.cluster.local (one prefix label)",
			domain:         "svc.cluster.local",
			wantMatched:    true,
			wantPattern:    "*.cluster.local",
			wantResolution: "nxdomain",
		},
		{
			name:        "no match for bare cluster.local (wildcard requires ≥1 prefix label)",
			domain:      "cluster.local",
			wantMatched: false,
		},
		{
			name:        "no match outside deny set",
			domain:      "example.com",
			wantMatched: false,
		},
		{
			name:        "different suffix",
			domain:      "foo.example.com",
			wantMatched: false,
		},
		{
			name:           "attacker.net wildcard matches multi-label",
			domain:         "c2.beacon.attacker.net",
			wantMatched:    true,
			wantPattern:    "*.attacker.net",
			wantResolution: "sinkhole",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, resolution, matched := MatchesDeny(tt.domain, denySet)
			if matched != tt.wantMatched {
				t.Fatalf("MatchesDeny(%q) matched = %v, want %v", tt.domain, matched, tt.wantMatched)
			}

			if !matched {
				return
			}

			if pattern != tt.wantPattern {
				t.Errorf("pattern = %q, want %q", pattern, tt.wantPattern)
			}

			if resolution != tt.wantResolution {
				t.Errorf("resolution = %q, want %q", resolution, tt.wantResolution)
			}
		})
	}
}
