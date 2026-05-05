// Package wildcard implements Cilium-style FQDN wildcard matching.
// Shared between the enforcer (DNS proxy) and store (anomaly detection).
package wildcard

import "strings"

// MatchesFQDN checks if a domain matches any pattern in the allowlist.
// Follows Cilium-style wildcard matching: each '*' replaces exactly one subdomain label.
//
//	*.example.com   matches a.example.com       (1 label)
//	*.example.com   does NOT match example.com  (0 labels)
//	*.example.com   does NOT match a.b.example.com (2 labels)
//	*.*.example.com matches a.b.example.com     (2 labels)
//
// Exact matches are also checked.
func MatchesFQDN(domain string, allowedFQDNs map[string]bool) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	// Exact match.
	if allowedFQDNs[domain] {
		return true
	}

	// Wildcard match: try replacing each leading label with '*'.
	// For a.b.example.com, try:
	//   *.b.example.com
	//   *.*.example.com  (via *.b... → *.*)
	// We walk up the domain labels and build wildcard patterns.
	labels := strings.Split(domain, ".")
	for depth := 1; depth < len(labels); depth++ {
		pattern := strings.Repeat("*.", depth) + strings.Join(labels[depth:], ".")
		if allowedFQDNs[pattern] {
			return true
		}
	}

	return false
}

// PortsForFQDN returns the allowed ports for a matching FQDN pattern.
// Returns nil if no match found.
func PortsForFQDN(domain string, fqdnPorts map[string]map[int]bool) map[int]bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	if ports, ok := fqdnPorts[domain]; ok {
		return ports
	}

	labels := strings.Split(domain, ".")
	for depth := 1; depth < len(labels); depth++ {
		pattern := strings.Repeat("*.", depth) + strings.Join(labels[depth:], ".")
		if ports, ok := fqdnPorts[pattern]; ok {
			return ports
		}
	}

	return nil
}

// ParentDomain returns the parent domain by stripping the first label.
// For "a.b.example.com" returns "b.example.com".
// For "example.com" returns "com".
// For single-label domains returns "".
func ParentDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	_, rest, found := strings.Cut(domain, ".")
	if !found {
		return ""
	}

	return rest
}

// IsWildcard returns true if the domain starts with "*.".
func IsWildcard(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

// MatchesSingle checks whether domain matches pattern using single-label
// wildcard semantics — each '*' replaces exactly one label. Use this for
// allow-side rules where `*.example.com` must NOT match `a.b.example.com`
// (Cilium security default).
func MatchesSingle(domain, pattern string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	pattern = strings.ToLower(pattern)

	if domain == pattern {
		return true
	}

	dLabels := strings.Split(domain, ".")
	pLabels := strings.Split(pattern, ".")

	if len(dLabels) != len(pLabels) {
		return false
	}

	for i, pl := range pLabels {
		if pl == "*" {
			continue
		}

		if pl != dLabels[i] {
			return false
		}
	}

	return true
}

// MatchesSuffix checks whether domain matches pattern using any-depth
// suffix semantics — a leading `*.` matches one or more labels. Use this
// for deny-side rules so `*.svc.cluster.local` catches multi-label k8s
// resolver search-path queries.
func MatchesSuffix(domain, pattern string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	pattern = strings.ToLower(pattern)

	if domain == pattern {
		return true
	}

	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := pattern[1:]

	return strings.HasSuffix(domain, suffix) && len(domain) > len(suffix)
}

// MatchesDeny checks if a domain matches any pattern in a deny set, using
// suffix-match semantics for wildcards (any depth of prefix labels).
//
// Deny uses suffix-match (not Cilium-style single-label) because the
// dominant use case is k8s-resolver search-domain cleanup: a query like
// `git.example.com.gitlab-runner.svc.cluster.local` (5 prefix
// labels) must match the deny pattern `*.svc.cluster.local`. Cilium-
// style wildcards would require a per-search-path entry. Allow-side
// wildcards stay single-label (MatchesFQDN) because the security
// concern there is the opposite: you don't want `*.example.com` to
// accidentally allow `attacker.bad.example.com`.
//
// denySet maps pattern → resolution ("sinkhole" or "nxdomain"). Returns
// the matching pattern and its resolution; matched=false on miss.
func MatchesDeny(domain string, denySet map[string]string) (string, string, bool) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	// Exact match first (O(1)).
	if r, ok := denySet[domain]; ok {
		return domain, r, true
	}

	// Wildcard suffix match: for each "*.suffix" pattern, check if
	// the domain ends with ".suffix" (including the dot). Return the
	// most specific (longest-suffix) match so that e.g. the domain
	// foo.svc.cluster.local prefers `*.svc.cluster.local` over
	// `*.cluster.local` when both are configured. Deterministic
	// regardless of map iteration order. Linear in the number of
	// deny patterns — acceptable for typical deny lists (<100
	// entries). If the list grows, switch to a suffix trie.
	var (
		bestPattern    string
		bestResolution string
		bestLen        int
	)

	for p, r := range denySet {
		if !strings.HasPrefix(p, "*.") {
			continue
		}

		suffix := p[1:] // ".svc.cluster.local"
		if !strings.HasSuffix(domain, suffix) || len(domain) <= len(suffix) {
			continue
		}

		if len(suffix) > bestLen {
			bestPattern = p
			bestResolution = r
			bestLen = len(suffix)
		}
	}

	if bestLen > 0 {
		return bestPattern, bestResolution, true
	}

	return "", "", false
}
