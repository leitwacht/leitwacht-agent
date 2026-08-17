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

	PatternFQDN        = "fqdn"
	PatternCIDR        = "cidr"
	PatternBuildVertex = "build_vertex"
)

// SystemRulePriority is the datapath priority reserved for entries that
// hold no position in any composed rule list and must outrank every
// rule: the DNS sinkhole deny, and CE's standalone `deny_ips:`
// blocklist. See the priority contract in egress.c.
const SystemRulePriority uint32 = 0

// RulePriority converts a rule's index in the composed rule list into
// the priority stored alongside its eBPF map entries. Lower wins, so
// the datapath reproduces the list's first-match-wins ordering rather
// than hardcoding a deny-beats-allow precedence.
//
// Offset by one to keep SystemRulePriority strictly ahead of the first
// rule.
func RulePriority(index int) uint32 {
	if index < 0 {
		return SystemRulePriority
	}

	return uint32(index) + 1 //nolint:gosec // composed lists are far below 2^32
}

// LSM feature mode values for the credwatch (credential-file access) and
// proc_mem (/proc/<pid>/mem read) LSM detectors. Carried per-project and
// per-job in the resolved policy so an operator can scope each detector
// independently of the global "is the LSM loaded" daemon switch.
//
//   - off:     don't attach the container to the detector (no monitoring)
//   - observe: emit the event but DON'T kill — sets the BPF
//     FLAG_OBSERVE_ONLY bit. For detonation sandboxes where killing at
//     first hit drops the kill chain we want to capture.
//   - enforce: emit the event AND kill/detach the container.
const (
	LSMModeOff     = "off"
	LSMModeObserve = "observe"
	LSMModeEnforce = "enforce"
)

// IsValidLSMMode reports whether s is one of the recognised LSM mode
// strings. The empty string is NOT valid here — callers that allow an
// unset/inherit value should check for "" before calling this.
func IsValidLSMMode(s string) bool {
	switch s {
	case LSMModeOff, LSMModeObserve, LSMModeEnforce:
		return true
	default:
		return false
	}
}

// Rule is one entry in an ordered policy list. The DNS proxy walks the
// composed slice top to bottom; the first match decides the outcome.
// Resolution is only meaningful when Action=deny AND PatternType=fqdn;
// Ports are only meaningful when Action=allow (nil = all ports).
// RequireBuildAttribution, on a build_vertex rule, denies egress whose
// BuildKit binding has no project_path override (= unattributed build).
type Rule struct {
	Pattern                 string `json:"pattern"`
	PatternType             string `json:"pattern_type"`
	Action                  string `json:"action"`
	Resolution              string `json:"resolution,omitempty"`
	Ports                   []int  `json:"ports,omitempty"`
	Reason                  string `json:"reason,omitempty"`
	Source                  string `json:"source,omitempty"`
	RequireBuildAttribution bool   `json:"require_build_attribution,omitempty"`
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

	// CredwatchMode / ProcMemMode are the project-level default LSM
	// enforcement mode (LSMMode* — "" means unset, resolved to enforce
	// for backward compatibility). The *JobModes maps hold per-job-name
	// overrides; an entry wins over the project default for that job.
	CredwatchMode     string            `json:"credwatch_mode,omitempty"`
	ProcMemMode       string            `json:"proc_mem_mode,omitempty"`
	CredwatchJobModes map[string]string `json:"credwatch_job_modes,omitempty"`
	ProcMemJobModes   map[string]string `json:"proc_mem_job_modes,omitempty"`
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

// CredwatchModeForJob returns the resolved credwatch LSM mode for a job:
// the per-job override if set, else the project default, else enforce.
func (p *ResolvedPolicy) CredwatchModeForJob(jobName string) string {
	return resolveLSMMode(p.CredwatchMode, p.CredwatchJobModes, jobName)
}

// ProcMemModeForJob returns the resolved proc_mem LSM mode for a job:
// the per-job override if set, else the project default, else enforce.
func (p *ResolvedPolicy) ProcMemModeForJob(jobName string) string {
	return resolveLSMMode(p.ProcMemMode, p.ProcMemJobModes, jobName)
}

// resolveLSMMode applies the override → project-default → enforce
// precedence. The enforce fallback preserves the pre-policy behaviour:
// before per-project modes existed, enabling an LSM detector globally
// killed on every hit, so an unset mode must keep killing.
func resolveLSMMode(projectDefault string, jobModes map[string]string, jobName string) string {
	if jobModes != nil {
		if m, ok := jobModes[jobName]; ok && m != "" {
			return m
		}
	}

	if projectDefault != "" {
		return projectDefault
	}

	return LSMModeEnforce
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
		// Collapse the LSM modes to the resolved value for this job; the
		// per-job maps are intentionally dropped from the job-scoped view.
		CredwatchMode: p.CredwatchModeForJob(jobName),
		ProcMemMode:   p.ProcMemModeForJob(jobName),
	}
}

// IsExpired returns true if the policy is past its TTL.
func (p *ResolvedPolicy) IsExpired() bool {
	return time.Since(p.FetchedAt) > p.TTL
}
