package enforcer

import (
	"sync"
	"time"
)

// DomainSourceAgentDNS is the tag stamped on violations whose Domain was
// attributed by the agent's own DNS cache. Mirrors
// domain.DomainSourceAgentDNS on the server; duplicated as a literal
// here so the enforcer has no store-layer dependency.
const DomainSourceAgentDNS = "agent_dns"

// Violation represents a single egress event.
type Violation struct {
	Domain     string `json:"domain"`
	IP         string `json:"ip,omitempty"`
	Port       int    `json:"port,omitempty"`
	PID        uint32 `json:"pid,omitempty"`
	Comm       string `json:"comm,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	// QueryType is the DNS RR type ("A", "AAAA", "TXT", ...) for
	// DNS-layer events; empty for packet-layer events (sinkhole_hit,
	// packet_dropped) which lack a direct query association.
	QueryType string `json:"query_type,omitempty"`
	// EnvNames lists environment variable names (NEVER values) the
	// offending process inherited from its execve. Populated only when
	// the recorder is configured to enrich; nil otherwise. Useful for
	// "what secrets could this process have exfiltrated?" forensics
	// without the report itself becoming a leak vector.
	EnvNames     []string  `json:"env_names,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Action       string    `json:"action"` // dns_blocked, packet_dropped, dns_observed, packet_observed, sinkhole_hit
	DomainSource string    `json:"domain_source,omitempty"`

	// BuildKit step attribution. Populated only when the egress
	// fired inside a BuildKit RUN cgroup and the SessionRegistry
	// had a binding for that cgroup id. All zero/empty fields on
	// non-BuildKit egress, which is the common case. The
	// AmbiguousCandidates slice carries the colliding vertex set
	// when the cgroup-join couldn't disambiguate across builds.
	BuildSessionRef          string               `json:"build_session_ref,omitempty"`
	BuildVertexDigest        string               `json:"build_vertex_digest,omitempty"`
	BuildVertexName          string               `json:"build_vertex_name,omitempty"`
	BuildAmbiguous           bool                 `json:"build_ambiguous,omitempty"`
	BuildAmbiguousCandidates []AmbiguousCandidate `json:"build_ambiguous_candidates,omitempty"`

	// BuildUnattributed marks egress seen in a watched BuildKit cgroup
	// subtree that the cgroup-join layer has not bound to any session
	// or vertex (no match yet, or no match at all). Such events carry
	// no build_* identity and must not be trusted as belonging to any
	// particular build.
	BuildUnattributed bool `json:"build_unattributed,omitempty"`

	// Per-row CI override fields, derived from the BuildKit session's
	// FrontendAttrs (build-args prefixed LEITWACHT_CI_*). Populated
	// at egress time when the binding's FrontendAttrs carry these
	// keys. When a persistent buildkitd serves many CI jobs from one
	// watched container, the report-level identity belongs to the
	// buildkitd pod, not the individual job — these fields let each
	// row attribute to its real CI job at the server.
	BuildProjectPath string `json:"build_project_path,omitempty"`
	BuildJobID       string `json:"build_job_id,omitempty"`
	BuildPipelineID  string `json:"build_pipeline_id,omitempty"`
	BuildJobName     string `json:"build_job_name,omitempty"`
	BuildJobStage    string `json:"build_job_stage,omitempty"`
	BuildGitRef      string `json:"build_git_ref,omitempty"`
	BuildJobURL      string `json:"build_job_url,omitempty"`
}

// DNSActivityEntry tracks DNS queries bucketed by (domain, query_type)
// so a domain queried for both A and TXT in the same bucket window
// surfaces as two distinct entries — qtype is a strong exfil signal
// (TXT/NULL/MX abuse for DNSCat-style tunnels).
type DNSActivityEntry struct {
	Domain      string   `json:"domain"`
	QueryType   string   `json:"query_type"` // "A", "AAAA", "TXT", "CNAME", "MX", ...
	QueryCount  int64    `json:"query_count"`
	ResolvedIPs []string `json:"resolved_ips"` //nolint:tagliatelle // IPs is a well-known abbreviation
	// ResolvedIPsDropped counts resolved-IP sightings not recorded in
	// ResolvedIPs because the per-entry cap was reached.
	ResolvedIPsDropped int64  `json:"resolved_ips_dropped,omitempty"` //nolint:tagliatelle // IPs is a well-known abbreviation
	Action             string `json:"action"`                         // dns_allowed, dns_blocked, dns_observed, dns_denied
	PID                uint32 `json:"pid,omitempty"`
	Comm               string `json:"comm,omitempty"`
	ParentComm         string `json:"parent_comm,omitempty"`
	BinaryPath         string `json:"binary_path,omitempty"`
	// EnvNames mirrors Violation.EnvNames: env-var names (never values)
	// for the PID that issued this query. Populated only when the
	// recorder has an enricher configured.
	EnvNames  []string  `json:"env_names,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// EgressStats is the complete stats collected during container enforcement.
type EgressStats struct {
	TotalBytesSent int64              `json:"total_bytes_sent"`
	DNSActivity    []DNSActivityEntry `json:"dns_activity"`
	Violations     []Violation        `json:"violations"`
	OverflowCount  int64              `json:"overflow_count"` // violations dropped due to cap
}

const (
	maxViolationsPerContainer = 1000
	maxViolationsPerBucket    = 100
	maxDNSEntriesPerContainer = 10000
	// dnsEnforcementHeadroom is carved out of maxDNSEntriesPerContainer for
	// blocked/denied entries: allowed/observed names can fill at most
	// (max - headroom) slots, so a job resolving thousands of allowed names
	// can never crowd out the evidence of its blocked ones.
	dnsEnforcementHeadroom = 1000
	// maxResolvedIPsPerEntry caps the distinct IPs kept per DNS entry.
	maxResolvedIPsPerEntry = 64
)

// isEnforcementDNSAction reports whether a DNS action is a block/deny event
// (as opposed to allowed/observed), which gets reserved capacity.
func isEnforcementDNSAction(action string) bool {
	return action == "dns_blocked" || action == "dns_denied"
}

// ViolationRecorder collects violations and DNS activity for a single container.
// Bare-IP packet violations are reconciled against dnsCache at pre-flush
// time (see SnapshotAndReset). That closes the concurrency race where
// server-side reconciliation could miss a bare violation because its
// report arrived between a DNS report's reverse-map read and its commit.
// dnsKey buckets DNS activity by (domain, qtype) so a TXT-flood and a
// casual A query against the same domain surface as separate entries.
type dnsKey struct {
	Domain string
	QType  string
}

type ViolationRecorder struct {
	mu          sync.Mutex
	violations  []Violation
	dnsActivity map[dnsKey]*DNSActivityEntry
	// dnsIPSets mirrors each entry's ResolvedIPs for O(1) dedup.
	dnsIPSets map[dnsKey]map[string]struct{}
	// dnsAllowedEntries counts non-enforcement entries in dnsActivity.
	dnsAllowedEntries int
	// dnsOverflow counts DNS (domain, qtype) entries dropped at the cap
	// this bucket; folded into the overflow count at SnapshotAndReset.
	dnsOverflow int64
	capped      bool
	capCount    int64 // count of violations after cap
	bucketMode  bool  // when true, uses maxViolationsPerBucket instead of maxViolationsPerContainer

	// dnsCache is optional. When present, RecordDNS populates it and
	// SnapshotAndReset/Snapshot attribute bare violations against it
	// before returning. Shared across recorders in the same netns so
	// per-cgroup packet recorders can consult the shared DNS recorder's
	// observations. nil in tests that don't exercise reconciliation.
	dnsCache *DNSCache

	// envNamesFn, when non-nil, is the live env-name reader (typically
	// procenv.Names). The recorder calls it at RECORD time — when the
	// offending PID is still alive — and caches the result for the
	// bucket window so the same PID making many events costs only one
	// /proc read. Cache is cleared at SnapshotAndReset.
	//
	// Capturing at record time (not flush) is the only way to attribute
	// short-lived processes (curl, dig — exactly the tools attackers
	// reach for one-shot exfil): by the time the bucket flushes, the
	// PID's /proc entry is gone.
	envNamesFn func(pid int) []string
	envCache   map[uint32][]string // PID -> names; cleared per bucket
}

// NewViolationRecorder creates a violation recorder for a single container.
// Pass nil for dnsCache when reconciliation isn't desired (tests, buildkit
// helpers) — it's a safe no-op on nil.
func NewViolationRecorder(dnsCache *DNSCache) *ViolationRecorder {
	return &ViolationRecorder{
		dnsActivity: make(map[dnsKey]*DNSActivityEntry),
		dnsIPSets:   make(map[dnsKey]map[string]struct{}),
		dnsCache:    dnsCache,
	}
}

// SetBucketMode enables per-bucket violation limits. Must be called before
// the first RecordViolation.
func (r *ViolationRecorder) SetBucketMode() {
	r.bucketMode = true
}

// SetEnvNamesEnricher installs a callback that turns a PID into a slice
// of environment variable NAMES (never values). When set, SnapshotAndReset
// invokes it once per unique non-zero PID in the bucket and attaches the
// result to every Violation with that PID. Pass nil to disable.
//
// Must be called before the first RecordViolation; the field is not
// mutex-protected because installation happens at recorder construction
// time in the production path.
func (r *ViolationRecorder) SetEnvNamesEnricher(fn func(pid int) []string) {
	r.envNamesFn = fn
}

// RecordViolation adds a violation. After the cap limit, switches to count-only.
func (r *ViolationRecorder) RecordViolation(v Violation) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.capped {
		r.capCount++

		return
	}

	// Snapshot env names while the offending PID is still alive. If
	// the recorder has no enricher this is a cheap no-op.
	if v.EnvNames == nil {
		v.EnvNames = r.snapshotEnv(v.PID)
	}

	r.violations = append(r.violations, v)

	capLimit := maxViolationsPerContainer
	if r.bucketMode {
		capLimit = maxViolationsPerBucket
	}

	if len(r.violations) >= capLimit {
		r.capped = true
	}
}

// RecordDNS records a DNS query and its resolved IPs, with optional
// process attribution. qtype is the DNS RR type as a string ("A",
// "AAAA", "TXT", ...) — feed it from dns.TypeToString[q.Qtype]. Activity
// is bucketed by (domain, qtype) so a domain queried for both A and TXT
// in one bucket window surfaces as separate entries.
func (r *ViolationRecorder) RecordDNS(domain, qtype, action string, ips []string, pid uint32, comm, parentComm, binaryPath string) {
	if domain == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	key := dnsKey{Domain: domain, QType: qtype}

	entry, ok := r.dnsActivity[key]
	if !ok {
		enforcement := isEnforcementDNSAction(action)

		if len(r.dnsActivity) >= maxDNSEntriesPerContainer ||
			(!enforcement && r.dnsAllowedEntries >= maxDNSEntriesPerContainer-dnsEnforcementHeadroom) {
			// Cap reached: stop tracking new (domain, qtype) pairs, but
			// count them so the loss is visible in the report.
			r.dnsOverflow++

			return
		}

		if !enforcement {
			r.dnsAllowedEntries++
		}

		entry = &DNSActivityEntry{
			Domain:     domain,
			QueryType:  qtype,
			Action:     action,
			PID:        pid,
			Comm:       comm,
			ParentComm: parentComm,
			BinaryPath: binaryPath,
			EnvNames:   r.snapshotEnv(pid),
			FirstSeen:  now,
		}
		r.dnsActivity[key] = entry
	}

	entry.QueryCount++
	entry.LastSeen = now

	// Merge new IPs into the entry's resolved set (O(1) dedup, capped).
	seen := r.dnsIPSets[key]
	if seen == nil {
		seen = make(map[string]struct{}, len(ips))
		r.dnsIPSets[key] = seen
	}

	for _, ip := range ips {
		if _, dup := seen[ip]; dup {
			continue
		}

		if len(entry.ResolvedIPs) >= maxResolvedIPsPerEntry {
			entry.ResolvedIPsDropped++

			continue
		}

		entry.ResolvedIPs = append(entry.ResolvedIPs, ip)
		seen[ip] = struct{}{}
	}

	// Populate the netns-wide DNS cache so packet violations flushed
	// by sibling recorders in later buckets can reconcile against this
	// observation. Nil cache = no-op.
	r.dnsCache.Record(domain, ips)
}

// Snapshot returns the current violations and DNS activity (read-only copy).
// Bare-IP violations are reconciled against the netns DNS cache so the
// snapshot reflects the agent's best attribution at read time.
func (r *ViolationRecorder) Snapshot() ([]Violation, []DNSActivityEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	violations := make([]Violation, len(r.violations))
	copy(violations, r.violations)

	reconcileBareViolations(violations, r.dnsCache)

	activity := make([]DNSActivityEntry, 0, len(r.dnsActivity))
	for _, entry := range r.dnsActivity {
		e := *entry
		e.ResolvedIPs = make([]string, len(entry.ResolvedIPs))
		copy(e.ResolvedIPs, entry.ResolvedIPs)
		activity = append(activity, e)
	}

	return violations, activity
}

// snapshotEnv returns env-var names for pid at this very moment,
// memoised for the current bucket. Caller must hold r.mu. Returns nil
// when env capture is disabled or the live read fails. Storing nil in
// the cache too means a subsequent event from the same PID doesn't
// re-walk /proc just to confirm the process still doesn't exist.
func (r *ViolationRecorder) snapshotEnv(pid uint32) []string {
	if r.envNamesFn == nil || pid == 0 {
		return nil
	}

	if names, hit := r.envCache[pid]; hit {
		return names
	}

	if r.envCache == nil {
		r.envCache = make(map[uint32][]string)
	}

	names := r.envNamesFn(int(pid))
	r.envCache[pid] = names

	return names
}

// reconcileBareViolations attaches a domain to any Violation with
// Domain=="" whose IP resolves via cache. Mutates in-place.
func reconcileBareViolations(violations []Violation, cache *DNSCache) {
	if cache == nil {
		return
	}

	for i := range violations {
		if violations[i].Domain != "" || violations[i].IP == "" {
			continue
		}

		if d := cache.Lookup(violations[i].IP); d != "" {
			violations[i].Domain = d
			violations[i].DomainSource = DomainSourceAgentDNS
		}
	}
}

// SnapshotAndReset atomically returns accumulated data and resets the recorder
// for the next bucket window. Takes ownership of the violations slice (no copy).
// Copies DNS entry values out of the pointer map. Returns overflow count from
// violations that exceeded the per-bucket cap.
func (r *ViolationRecorder) SnapshotAndReset() ([]Violation, []DNSActivityEntry, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Take ownership of violations slice — no copy needed.
	violations := r.violations
	r.violations = nil

	reconcileBareViolations(violations, r.dnsCache)

	overflow := r.capCount + r.dnsOverflow
	r.dnsOverflow = 0
	r.dnsAllowedEntries = 0
	r.capped = false
	r.capCount = 0

	// Copy DNS entries out of the pointer map.
	activity := make([]DNSActivityEntry, 0, len(r.dnsActivity))
	for _, entry := range r.dnsActivity {
		e := *entry
		e.ResolvedIPs = make([]string, len(entry.ResolvedIPs))
		copy(e.ResolvedIPs, entry.ResolvedIPs)
		activity = append(activity, e)
	}

	// Reset DNS map and per-bucket env cache for the next window.
	r.dnsActivity = make(map[dnsKey]*DNSActivityEntry)
	r.dnsIPSets = make(map[dnsKey]map[string]struct{})
	r.envCache = nil

	return violations, activity, overflow
}
