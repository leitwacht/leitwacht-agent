// Package ruleyaml is the CE YAML rule loader. It parses a `rules.yaml`
// file, validates it, and exposes the parsed rules through the
// agentcore policy.Source interface so the same handler / cache
// pipeline used by EE drives enforcement on CE.
//
// The schema is documented in ce/SCHEMA.md and stable across the v1
// schema_version. Breaking changes will require a v2 with explicit
// migration notes.
package ruleyaml

// File is the top-level shape of a rules.yaml document.
type File struct {
	SchemaVersion   int      `yaml:"schema_version"`
	Scopes          []Scope  `yaml:"scopes"`
	ReservedDomains []string `yaml:"reserved_domains,omitempty"`
}

// Scope groups rule sets under an operator-named identifier. CE matches a
// running container to a scope using the value of an env var or label
// configured via SCOPE_LABEL / SCOPE_ENV on the agent daemon. Scope name
// "default" is used as the fallback when no match is found.
type Scope struct {
	Name          string            `yaml:"name"`
	DefaultAction string            `yaml:"default_action"`
	JobActions    map[string]string `yaml:"job_actions,omitempty"`
	RuleSets      map[string][]Rule `yaml:"rule_sets"`
	DenyIPs       []DenyIP          `yaml:"deny_ips,omitempty"`
}

// Rule is one entry in a scope's rule list. PatternType accepts the
// human-friendly forms `domain`, `wildcard`, `ip`, `cidr`; the loader
// normalises to agentcore's two pattern types (`fqdn`, `cidr`).
type Rule struct {
	Pattern     string `yaml:"pattern"`
	PatternType string `yaml:"pattern_type"`
	Action      string `yaml:"action"`
	Resolution  string `yaml:"resolution,omitempty"`
	Ports       []int  `yaml:"ports,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
}

// DenyIP is an IP/port deny rule that bypasses DNS-name resolution and
// is enforced directly by the eBPF deny map.
type DenyIP struct {
	IP   string `yaml:"ip"`
	Port int    `yaml:"port,omitempty"`
}

// Action / pattern type strings accepted in YAML. The loader normalises
// every input to one of these constants before construction.
const (
	ActionAllow = "allow"
	ActionBlock = "block"
	ActionAudit = "audit"

	PatternDomain   = "domain"
	PatternWildcard = "wildcard"
	PatternIP       = "ip"
	PatternCIDR     = "cidr"

	DefaultScopeName = "default"
)
