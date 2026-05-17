package policy

import (
	"time"
)

// Deny resolution values. Mirror domain.DenyResolution* constants.
const (
	DenyResolutionSinkhole = "sinkhole"
	DenyResolutionNXDomain = "nxdomain"
)

// Action / PatternType values. Mirror domain.RuleAction* and
// domain.RulePattern* — duplicated here so the enforcer package can
// depend on policy without pulling in domain (and thus GORM).
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionAudit = "audit"
	ActionBlock = "block"

	PatternFQDN = "fqdn"
	PatternCIDR = "cidr"
)

// Rule is one entry in an ordered policy list. The DNS proxy walks the
// composed slice top to bottom; the first match decides the outcome.
// Resolution is only meaningful when Action=deny AND PatternType=fqdn;
// Ports are only meaningful when Action=allow (nil = all ports).
type Rule struct {
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
	Action      string `json:"action"`
	Resolution  string `json:"resolution,omitempty"`
	Ports       []int  `json:"ports,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Source      string `json:"source,omitempty"`
}

// DenyIP represents an IP deny rule. Fed into the eBPF deny map.
type DenyIP struct {
	IP   string `json:"ip"`
	Port int    `json:"port"` // 0 = all ports
}

// DenyIPKey is the lookup key for the deny IP set.
type DenyIPKey struct {
	IP   string
	Port int
}

// ResolvedPolicy holds the fully-resolved egress policy for a project.
// RuleSets is keyed by job_name, with the empty string holding the
// default list used when the agent cannot identify the current job.
// Each list is already composed specific-first by the server; the
// agent walks it verbatim.
type ResolvedPolicy struct {
	ProjectPath string             `json:"project_path"`
	Action      string             `json:"action"` // block, audit, allow (project default)
	JobActions  map[string]string  `json:"job_actions,omitempty"`
	RuleSets    map[string][]Rule  `json:"rule_sets"`
	DenyIPs     []DenyIP           `json:"deny_ips,omitempty"` //nolint:tagliatelle // IPs is a well-known abbreviation
	DenyIPSet   map[DenyIPKey]bool `json:"-"`
	Enrolled    bool               `json:"enrolled"`
	Version     int                `json:"version"`
	FetchedAt   time.Time          `json:"fetched_at"`
	TTL         time.Duration      `json:"ttl"`
}

// ActionForJob returns the enforcement action for a specific job name,
// falling back to the project-level action if no per-job override is set.
func (p *ResolvedPolicy) ActionForJob(jobName string) string {
	if p.JobActions != nil {
		if action, ok := p.JobActions[jobName]; ok && action != "" {
			return action
		}
	}

	return p.Action
}

// BuildLookups populates DenyIPSet for O(1) IP lookup. Rule slices are
// already ordered by the server and don't need pre-indexing — the DNS
// proxy walks them per query.
func (p *ResolvedPolicy) BuildLookups() {
	p.DenyIPSet = make(map[DenyIPKey]bool, len(p.DenyIPs))
	for _, dip := range p.DenyIPs {
		p.DenyIPSet[DenyIPKey(dip)] = true
	}
}

// RulesForJob returns the ordered rule slice for a job. Falls back to the
// default set (JobName="") when the job has no dedicated list. Returns an
// empty slice if neither exists so callers can range without nil checks.
func (p *ResolvedPolicy) RulesForJob(jobName string) []Rule {
	if p.RuleSets != nil {
		if rules, ok := p.RuleSets[jobName]; ok {
			return rules
		}

		if rules, ok := p.RuleSets[""]; ok {
			return rules
		}
	}

	return nil
}

// ForJob returns a ResolvedPolicy view scoped to jobName. The returned
// value shares the underlying rule slice — callers must not mutate it.
func (p *ResolvedPolicy) ForJob(jobName string) *ResolvedPolicy {
	return &ResolvedPolicy{
		ProjectPath: p.ProjectPath,
		Action:      p.ActionForJob(jobName),
		JobActions:  p.JobActions,
		RuleSets:    map[string][]Rule{"": p.RulesForJob(jobName)},
		DenyIPs:     p.DenyIPs,
		DenyIPSet:   p.DenyIPSet,
		Enrolled:    p.Enrolled,
		Version:     p.Version,
		FetchedAt:   p.FetchedAt,
		TTL:         p.TTL,
	}
}

// IsExpired returns true if the policy is past its TTL.
func (p *ResolvedPolicy) IsExpired() bool {
	return time.Since(p.FetchedAt) > p.TTL
}
