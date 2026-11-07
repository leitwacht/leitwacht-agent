package ruleyaml

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gopkg.in/yaml.v3"
)

const supportedSchemaVersion = 1

// Loader implements policy.Source by reading a rules.yaml file and
// satisfying policy.WatcherReadiness. Hot-reload runs off an fsnotify
// watch; the parsed snapshot is swapped atomically.
type Loader struct {
	path string
	log  *slog.Logger

	snapshot atomic.Pointer[snapshot]
	ready    atomic.Bool
	version  atomic.Int64

	onReload atomic.Pointer[func()]
}

// SetOnReload registers fn to run after every successful hot reload
// (not after the initial load). Used to tell policy consumers that rules
// changed. fn must not block.
func (l *Loader) SetOnReload(fn func()) {
	if fn == nil {
		l.onReload.Store(nil)

		return
	}

	l.onReload.Store(&fn)
}

type snapshot struct {
	scopes       map[string]*policy.ResolvedPolicy
	defaultScope *policy.ResolvedPolicy
}

// New creates a Loader and performs the initial parse. Returns an error
// if the file cannot be read or the schema is invalid — the daemon
// refuses to start with bad rules rather than silently allowing all
// egress.
func New(path string, log *slog.Logger) (*Loader, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve rules path: %w", err)
	}

	// Resolve symlinks so the path we compare against fsnotify events
	// matches what the kernel reports. On darwin /var → /private/var
	// trips this; on Linux atomic ConfigMap projection (..data symlink)
	// also depends on it.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}

	l := &Loader{path: abs, log: log}

	if err := l.reload(); err != nil {
		return nil, err
	}

	l.ready.Store(true)

	return l, nil
}

// Resolve returns the policy for projectPath. CE matches on scope name:
// callers pass either the scope name (preferred — set via container env
// or label) or any string. On miss the "default" scope is returned if
// configured; otherwise (nil, false, nil).
func (l *Loader) Resolve(projectPath string) (*policy.ResolvedPolicy, bool, error) {
	snap := l.snapshot.Load()
	if snap == nil {
		return nil, false, nil
	}

	if pol, ok := snap.scopes[projectPath]; ok {
		return pol, true, nil
	}

	if snap.defaultScope != nil {
		// Clone so callers that mutate ProjectPath for ForJob() etc. don't
		// pollute the shared default.
		clone := *snap.defaultScope
		clone.ProjectPath = projectPath
		return &clone, true, nil
	}

	return nil, false, nil
}

// Ready satisfies policy.WatcherReadiness. CE is ready as soon as the
// initial parse succeeded.
func (l *Loader) Ready() bool { return l.ready.Load() }

// Run watches the rules file for changes and reloads on writes. Returns
// when ctx is cancelled. The optional ready channel, if non-nil, is
// closed once the fsnotify watch is in place — useful for tests that
// need to write the file after Run() is observing.
func (l *Loader) Run(stop <-chan struct{}) error {
	return l.runWithReady(stop, nil)
}

// RunWithReady is Run plus a ready signal. Production callers use Run;
// tests that race writes against watcher startup pass a non-nil ready
// channel and wait on it before writing.
func (l *Loader) RunWithReady(stop <-chan struct{}, ready chan<- struct{}) error {
	return l.runWithReady(stop, ready)
}

func (l *Loader) runWithReady(stop <-chan struct{}, ready chan<- struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	defer w.Close()

	dir := filepath.Dir(l.path)
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}

	if ready != nil {
		close(ready)
	}

	// Compare on basename rather than the full path. A symlinked tmpdir
	// (darwin /var → /private/var) and Kubernetes ConfigMap projection
	// (..data/rules.yaml swap) both deliver events with paths that
	// don't equal l.path verbatim, but the basename always matches.
	want := filepath.Base(l.path)

	// Coalesce bursts of writes (editors, ConfigMap atomic-rename) into a
	// single reload after a short quiet period.
	const debounce = 250 * time.Millisecond

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	resetTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			if err := l.reload(); err != nil {
				l.log.Error("rules reload failed (keeping previous snapshot)",
					"path", l.path, "error", err)
				return
			}
			l.log.Info("rules reloaded", "path", l.path, "version", l.version.Load())

			if fn := l.onReload.Load(); fn != nil {
				(*fn)()
			}
		})
	}

	for {
		select {
		case <-stop:
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if filepath.Base(ev.Name) != want {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				resetTimer()
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			l.log.Warn("fsnotify error", "error", err)
		}
	}
}

// Version returns a monotonic counter advanced on every reload attempt
// (a failed reload consumes a number without replacing the snapshot).
// Surfaced for diagnostic logging — callers should not rely on
// the exact integer for caching decisions.
func (l *Loader) Version() int64 { return l.version.Load() }

func (l *Loader) reload() error {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", l.path, err)
	}

	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	if f.SchemaVersion != supportedSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (want %d)",
			f.SchemaVersion, supportedSchemaVersion)
	}

	if len(f.Scopes) == 0 {
		return errors.New("no scopes defined")
	}

	// Increment version *before* building the snapshot so concurrent
	// reload paths (the test path that calls reload() directly bypasses
	// the debounce serialisation) can't both stamp the same version on
	// two snapshots.
	version := int(l.version.Add(1))

	snap, err := buildSnapshot(&f, version)
	if err != nil {
		return err
	}

	l.snapshot.Store(snap)

	return nil
}

func buildSnapshot(f *File, version int) (*snapshot, error) {
	now := time.Now()
	out := &snapshot{scopes: make(map[string]*policy.ResolvedPolicy, len(f.Scopes))}

	for i := range f.Scopes {
		s := &f.Scopes[i]

		if s.Name == "" {
			return nil, fmt.Errorf("scope[%d]: name is required", i)
		}

		action, err := normaliseAction(s.DefaultAction, ActionAllow)
		if err != nil {
			return nil, fmt.Errorf("scope %q: default_action: %w", s.Name, err)
		}

		jobActions := make(map[string]string, len(s.JobActions))
		for job, ja := range s.JobActions {
			a, err := normaliseAction(ja, "")
			if err != nil {
				return nil, fmt.Errorf("scope %q: job_actions[%q]: %w", s.Name, job, err)
			}
			jobActions[job] = a
		}

		ruleSets := make(map[string][]policy.Rule, len(s.RuleSets))
		// Always provide a default catch-all key so the handler can range.
		if _, ok := s.RuleSets[""]; !ok {
			ruleSets[""] = nil
		}

		for jobName, rules := range s.RuleSets {
			converted, err := convertRules(rules)
			if err != nil {
				return nil, fmt.Errorf("scope %q: rule_sets[%q]: %w", s.Name, jobName, err)
			}
			ruleSets[jobName] = converted
		}

		denyIPs, denyIPSet, err := buildDenyIPs(s.DenyIPs)
		if err != nil {
			return nil, fmt.Errorf("scope %q: deny_ips: %w", s.Name, err)
		}

		credwatchMode, err := normaliseLSMMode(s.Credwatch)
		if err != nil {
			return nil, fmt.Errorf("scope %q: credwatch: %w", s.Name, err)
		}

		procMemMode, err := normaliseLSMMode(s.ProcMem)
		if err != nil {
			return nil, fmt.Errorf("scope %q: proc_mem: %w", s.Name, err)
		}

		credwatchJobs, procMemJobs, err := buildJobModes(s.JobOverrides)
		if err != nil {
			return nil, fmt.Errorf("scope %q: job_overrides: %w", s.Name, err)
		}

		pol := &policy.ResolvedPolicy{
			ProjectPath:       s.Name,
			Action:            action,
			JobActions:        jobActions,
			RuleSets:          ruleSets,
			DenyIPs:           denyIPs,
			DenyIPSet:         denyIPSet,
			Enrolled:          true,
			Version:           version,
			FetchedAt:         now,
			TTL:               24 * time.Hour, // CE serves from snapshot; the cache TTL is irrelevant.
			CredwatchMode:     credwatchMode,
			ProcMemMode:       procMemMode,
			CredwatchJobModes: credwatchJobs,
			ProcMemJobModes:   procMemJobs,
		}

		if _, dup := out.scopes[s.Name]; dup {
			return nil, fmt.Errorf("scope %q: duplicate name", s.Name)
		}
		out.scopes[s.Name] = pol

		if s.Name == DefaultScopeName {
			out.defaultScope = pol
		}
	}

	return out, nil
}

func convertRules(in []Rule) ([]policy.Rule, error) {
	out := make([]policy.Rule, 0, len(in))
	for i, r := range in {
		action, err := normaliseAction(r.Action, "")
		if err != nil {
			return nil, fmt.Errorf("rule[%d] %q: action: %w", i, r.Pattern, err)
		}

		// agentcore action vocabulary at rule scope is allow|deny only.
		// Per-rule `audit` is rejected because it doesn't have a
		// distinct enforcement semantics yet — it would silently behave
		// as allow and surprise operators. Audit-mode is a project-
		// level decision: set `default_action: audit` on the scope.
		if action == ActionAudit {
			return nil, fmt.Errorf("rule[%d] %q: action: audit is not supported per-rule; "+
				"use default_action: audit on the scope to put the whole scope in audit mode", i, r.Pattern)
		}
		if action == ActionBlock {
			action = policy.ActionDeny
		}

		pt, pattern, err := normalisePattern(r.PatternType, r.Pattern, action)
		if err != nil {
			return nil, fmt.Errorf("rule[%d] %q: %w", i, r.Pattern, err)
		}

		// Ports on a domain/wildcard deny rule are not used by the
		// datapath (the whole name is blocked), so they are ignored.
		ports := r.Ports
		if action == policy.ActionDeny && pt == policy.PatternFQDN {
			ports = nil
		} else if err := validatePorts(ports, pt); err != nil {
			return nil, fmt.Errorf("rule[%d] %q: %w", i, r.Pattern, err)
		}

		// Reject `allow + domain/wildcard` rules without explicit ports.
		// When a rule lists no ports the DNS proxy seeds a built-in
		// default of [443, 80], which is rarely what the operator meant
		// (and for a CIDR rule "no ports" means any port, a different
		// meaning). Both CE and EE force operators to spell out the
		// ports they actually need so the rule says what it enforces.
		if action == policy.ActionAllow && pt == policy.PatternFQDN && len(r.Ports) == 0 {
			return nil, fmt.Errorf("rule[%d] %q: allow + domain/wildcard rule must specify ports "+
				"(e.g., ports: [443]); empty ports would fall back to the built-in default (443, 80)", i, r.Pattern)
		}

		resolution := r.Resolution
		if action == policy.ActionDeny && pt == policy.PatternFQDN && resolution == "" {
			resolution = policy.DenyResolutionNXDomain
		}

		out = append(out, policy.Rule{
			Pattern:     pattern,
			PatternType: pt,
			Action:      action,
			Resolution:  resolution,
			Ports:       ports,
			Reason:      r.Reason,
			Source:      "ce-yaml",
		})
	}
	return out, nil
}

func normaliseAction(in, fallback string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(in))
	if v == "" {
		if fallback == "" {
			return "", errors.New("action is required")
		}
		v = fallback
	}
	switch v {
	case ActionAllow, ActionBlock, ActionAudit, policy.ActionDeny:
		return v, nil
	default:
		return "", fmt.Errorf("unknown action %q (want allow|block|audit)", in)
	}
}

// normaliseLSMMode validates an off|observe|enforce mode string. Empty is
// allowed and returns "" (inherit/unset) so the agent's policy resolver
// applies its enforce default rather than the loader baking it in.
func normaliseLSMMode(in string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(in))
	if v == "" {
		return "", nil
	}

	if !policy.IsValidLSMMode(v) {
		return "", fmt.Errorf("unknown mode %q (want off|observe|enforce)", in)
	}

	return v, nil
}

// buildJobModes splits per-job overrides into the two parallel maps the
// agent policy carries (credwatch / proc_mem). Jobs that override neither
// detector are omitted so the maps stay nil when unused.
func buildJobModes(in map[string]JobOverride) (credwatch, procMem map[string]string, err error) {
	for job, ov := range in {
		cw, err := normaliseLSMMode(ov.Credwatch)
		if err != nil {
			return nil, nil, fmt.Errorf("job_overrides[%q]: credwatch: %w", job, err)
		}

		pm, err := normaliseLSMMode(ov.ProcMem)
		if err != nil {
			return nil, nil, fmt.Errorf("job_overrides[%q]: proc_mem: %w", job, err)
		}

		if cw != "" {
			if credwatch == nil {
				credwatch = make(map[string]string)
			}
			credwatch[job] = cw
		}

		if pm != "" {
			if procMem == nil {
				procMem = make(map[string]string)
			}
			procMem[job] = pm
		}
	}

	return credwatch, procMem, nil
}

// validatePorts checks rule ports against what the datapath can key on.
// The eBPF allow/deny keys hold a uint16, so an out-of-range value would
// silently wrap (65979 -> 443, 65536 -> 0 = any port). FQDN rules need a
// real port (1..65535); CIDR rules also accept 0, the any-port wildcard.
func validatePorts(ports []int, patternType string) error {
	lo := 1
	if patternType == policy.PatternCIDR {
		lo = 0
	}

	for _, p := range ports {
		if p < lo || p > maxPort {
			return fmt.Errorf("port %d out of range (want %d..%d)", p, lo, maxPort)
		}
	}

	return nil
}

const maxPort = 65535

// normaliseFQDN lower-cases a domain/wildcard pattern, strips a single
// trailing dot (the DNS root label) and rejects anything that is not a
// valid hostname pattern: IP literals, schemes, ports, paths, empty or
// over-long labels, non-ASCII, and wildcards the matcher does not honour.
// Such rules would never match a DNS query name, so they would silently
// never apply. Allow rules may use `*` as a whole label anywhere; deny
// rules only as the first label (`*.example.com`).
func normaliseFQDN(pattern, action string) (string, error) {
	p := strings.ToLower(strings.TrimSuffix(pattern, "."))
	if p == "" {
		return "", errors.New("pattern is required")
	}

	if strings.Contains(p, "://") {
		return "", fmt.Errorf("pattern %q must be a bare hostname, not a URL (drop the scheme)", pattern)
	}

	if net.ParseIP(p) != nil {
		return "", fmt.Errorf("pattern %q is an IP address; use pattern_type ip", pattern)
	}

	if strings.Contains(p, ":") {
		return "", fmt.Errorf("pattern %q must not include a port or IPv6 address; "+
			"use the ports field (and pattern_type ip/cidr for addresses)", pattern)
	}

	for _, r := range p {
		if r > 127 {
			return "", fmt.Errorf("pattern %q contains non-ASCII characters; "+
				"use the punycode (xn--) form of internationalised names", pattern)
		}

		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '*' || r == '.') {
			return "", fmt.Errorf("pattern %q must be a bare hostname (invalid character %q)", pattern, r)
		}
	}

	if len(p) > 253 {
		return "", fmt.Errorf("pattern %q is longer than 253 characters", pattern)
	}

	if p == "*" {
		return "", fmt.Errorf("pattern %q would match every name; use a domain like *.example.com", pattern)
	}

	labels := strings.Split(p, ".")
	for i, l := range labels {
		switch {
		case l == "":
			return "", fmt.Errorf("pattern %q has an empty label", pattern)
		case len(l) > 63:
			return "", fmt.Errorf("pattern %q has a label longer than 63 characters", pattern)
		case strings.Contains(l, "*") && l != "*":
			return "", fmt.Errorf("pattern %q: '*' must be a whole label (e.g. *.example.com)", pattern)
		case l == "*" && i > 0 && action == policy.ActionDeny:
			return "", fmt.Errorf("pattern %q: deny rules support '*' only as the first label", pattern)
		}
	}

	return p, nil
}

// singleHostIPv4 parses an IPv4 address or /32 CIDR. IPv6 and multi-host
// prefixes are rejected because the egress maps are exact-match IPv4
// hashes; the enforcer would otherwise skip the rule with only a warning.
func singleHostIPv4(pattern string, allowPrefix bool) (string, error) {
	if strings.Contains(pattern, ":") {
		return "", fmt.Errorf("%q: IPv6 is not supported (the egress filter handles IPv4 only)", pattern)
	}

	addr, prefix, hasPrefix := strings.Cut(pattern, "/")

	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid IPv4 address %q", pattern)
	}

	if hasPrefix {
		if !allowPrefix {
			return "", fmt.Errorf("invalid ip %q (use pattern_type cidr for prefixes)", pattern)
		}

		if prefix != "32" {
			return "", fmt.Errorf("cidr %q: only single-host /32 is supported "+
				"(the allow/deny maps are exact-match); list each address or use a domain rule", pattern)
		}
	}

	return ip.To4().String() + "/32", nil
}

func normalisePattern(ptype, pattern, action string) (string, string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", "", errors.New("pattern is required")
	}

	switch strings.ToLower(strings.TrimSpace(ptype)) {
	case "", PatternDomain, PatternWildcard:
		p, err := normaliseFQDN(pattern, action)
		if err != nil {
			return "", "", err
		}

		return policy.PatternFQDN, p, nil
	case PatternIP:
		p, err := singleHostIPv4(pattern, false)
		if err != nil {
			return "", "", err
		}

		return policy.PatternCIDR, p, nil
	case PatternCIDR:
		// A /32 written as cidr is accepted and equivalent to pattern_type ip.
		p, err := singleHostIPv4(pattern, true)
		if err != nil {
			return "", "", err
		}

		return policy.PatternCIDR, p, nil
	default:
		return "", "", fmt.Errorf("unknown pattern_type %q", ptype)
	}
}

func buildDenyIPs(in []DenyIP) ([]policy.DenyIP, map[policy.DenyIPKey]bool, error) {
	out := make([]policy.DenyIP, 0, len(in))
	set := make(map[policy.DenyIPKey]bool, len(in))
	for i, d := range in {
		addr, err := singleHostIPv4(strings.TrimSpace(d.IP), false)
		if err != nil {
			return nil, nil, fmt.Errorf("deny_ips[%d]: %w", i, err)
		}
		if d.Port < 0 || d.Port > maxPort {
			return nil, nil, fmt.Errorf("deny_ips[%d]: port %d out of range (want 0..%d)", i, d.Port, maxPort)
		}
		entry := policy.DenyIP{IP: strings.TrimSuffix(addr, "/32"), Port: d.Port}
		out = append(out, entry)
		set[policy.DenyIPKey{IP: entry.IP, Port: entry.Port}] = true
	}
	return out, set, nil
}
