package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// BuildPolicyMode is the enforcement mode of a BuildKit RUN-step policy.
type BuildPolicyMode string

const (
	// BuildModeAudit observes every connection; nothing is dropped.
	BuildModeAudit BuildPolicyMode = "audit"
	// BuildModeShadow passes every connection and records would_block
	// for the ones the policy would deny.
	BuildModeShadow BuildPolicyMode = "shadow"
	// BuildModeEnforce drops connections the policy denies.
	BuildModeEnforce BuildPolicyMode = "enforce"
)

// ParseBuildPolicyMode canonicalises a configured mode string. The empty
// string is audit. Anything else unknown is an error: a typo must not
// silently select a different mode.
func ParseBuildPolicyMode(s string) (BuildPolicyMode, error) {
	switch BuildPolicyMode(s) {
	case "", BuildModeAudit:
		return BuildModeAudit, nil
	case BuildModeShadow:
		return BuildModeShadow, nil
	case BuildModeEnforce:
		return BuildModeEnforce, nil
	default:
		return "", fmt.Errorf("%w: %q (want audit|shadow|enforce)", ErrBuildPolicyMode, s)
	}
}

// ErrBuildPolicyMode is returned for an unrecognised build mode string.
var ErrBuildPolicyMode = errors.New("invalid buildkit enforcement mode")

// ErrBuildPolicyUnavailable is returned by a BuildPolicySource that has
// no policy for the project (not fetched yet, no entry, source down).
// The binder treats it as audit + flag, never as deny.
var ErrBuildPolicyUnavailable = errors.New("buildkit policy unavailable")

// BuildIPRule is one IPv4 allow or deny entry, rendered exactly as the
// per-pod path renders it (see collectIPRules): Port 0 means any port,
// Prio is the rule's position in the composed list (policy.RulePriority,
// lower wins; policy.SystemRulePriority for standalone deny_ips).
type BuildIPRule struct {
	IP    string
	Port  int
	Allow bool
	Prio  uint32
}

// BuildFQDNRule is a name rule, enforced by the build DNS proxy: an
// allow match seeds the slot's DNS-derived allow map (Ports, Prio); a
// deny match answers per Resolution in enforce mode.
type BuildFQDNRule struct {
	Pattern string
	Ports   []int
	Allow   bool
	Prio    uint32
	// Resolution is the deny answer: policy.DenyResolutionSinkhole (the
	// default, also for "") or policy.DenyResolutionNXDomain.
	Resolution string
}

// BuildPolicy is the rendered egress policy a build step runs under.
type BuildPolicy struct {
	ProjectPath string
	// JobName is the job the policy was rendered for ("" = project
	// default list).
	JobName string
	// Mode is the effective mode: the source folds the project/job
	// action (audit/allow/block), enrolment and the operator's build
	// rollout setting into one of audit|shadow|enforce. The agent
	// applies it verbatim.
	Mode BuildPolicyMode
	// Version changes whenever the rendered rules or mode change; slots
	// are keyed by it.
	Version int

	IPRules   []BuildIPRule
	FQDNRules []BuildFQDNRule
}

// BuildPolicySource supplies per-(project, job) policies to the build
// policy binder. It is edition-neutral: CE implements it from its YAML
// rules, EE from the policy cache.
type BuildPolicySource interface {
	// Policy returns the policy for projectPath and jobName (jobName ""
	// asks for the project-default list; a job without a dedicated list
	// falls back to it). It must return ErrBuildPolicyUnavailable (or
	// wrap it) when there is none. It is called from the join path with a
	// short deadline, so a slow source should answer from cache.
	Policy(ctx context.Context, projectPath, jobName string) (BuildPolicy, error)

	// Watch registers fn to be called when the policy of projectPath
	// changed; projectPath "" means "anything may have changed". The
	// returned func unregisters. Calls may come from any goroutine and
	// must not block the source.
	Watch(fn func(projectPath string)) (cancel func())
}

// RenderBuildPolicy renders a resolved policy for one job into a
// BuildPolicy using the same rule rendering as the per-pod path. mode is
// the operator's build rollout setting (shadow|enforce); it applies only
// when the job's effective action is block and the project is enrolled,
// otherwise the policy is audit.
func RenderBuildPolicy(pol *policy.ResolvedPolicy, jobName string, mode BuildPolicyMode, log *slog.Logger) BuildPolicy {
	if log == nil {
		log = slog.Default()
	}

	eff := BuildModeAudit

	if pol.Enrolled && pol.ActionForJob(jobName) == policy.ActionBlock &&
		(mode == BuildModeShadow || mode == BuildModeEnforce) {
		eff = mode
	}

	// collectIPRules renders the default ("") list; scope it to the job.
	view := pol.ForJob(jobName)
	deny, allow := collectIPRules(view, log)

	bp := BuildPolicy{
		ProjectPath: pol.ProjectPath,
		JobName:     jobName,
		Mode:        eff,
		Version:     pol.Version,
	}

	for _, e := range deny {
		bp.IPRules = append(bp.IPRules, BuildIPRule{IP: e.Key.IP, Port: e.Key.Port, Allow: false, Prio: e.Prio})
	}

	for _, e := range allow {
		bp.IPRules = append(bp.IPRules, BuildIPRule{IP: e.Key.IP, Port: e.Key.Port, Allow: true, Prio: e.Prio})
	}

	for i, r := range view.RulesForJob("") {
		if r.PatternType != policy.PatternFQDN {
			continue
		}

		bp.FQDNRules = append(bp.FQDNRules, BuildFQDNRule{
			Pattern: r.Pattern,
			Ports:   r.Ports,
			Allow:   r.Action != policy.ActionDeny,
			Prio:    policy.RulePriority(i),

			Resolution: r.Resolution,
		})
	}

	return bp
}

// ProviderBuildPolicySource adapts a policy.Provider (CE's YAML resolver,
// EE's policy cache) to BuildPolicySource. EE uses the same adapter over
// its policycache and supplies the per-project mode from the server's
// build_mode through modeFn. The adapter folds the mode into the policy
// version itself, so callers never replicate that.
type ProviderBuildPolicySource struct {
	provider policy.Provider
	mode     func(project string) BuildPolicyMode
	log      *slog.Logger

	mu       sync.Mutex
	watchers map[int]func(string)
	next     int
}

// NewProviderBuildPolicySource wires provider as a BuildPolicySource.
// mode(project) is the operator's rollout setting for that project (shadow
// or enforce; nil or audit means audit). It is read on every Policy call,
// so a rollout change needs only Notify(project).
func NewProviderBuildPolicySource(provider policy.Provider, mode func(project string) BuildPolicyMode, log *slog.Logger) *ProviderBuildPolicySource {
	if log == nil {
		log = slog.Default()
	}

	return &ProviderBuildPolicySource{provider: provider, mode: mode, log: log, watchers: map[int]func(string){}}
}

// Policy implements BuildPolicySource.
func (s *ProviderBuildPolicySource) Policy(ctx context.Context, projectPath, jobName string) (BuildPolicy, error) {
	pol, err := s.provider.GetPolicy(ctx, projectPath)
	if err != nil || pol == nil {
		return BuildPolicy{}, fmt.Errorf("%w: %s", ErrBuildPolicyUnavailable, projectPath)
	}

	mode := BuildModeAudit
	if s.mode != nil {
		mode = s.mode(projectPath)
	}

	bp := RenderBuildPolicy(pol, jobName, mode, s.log)
	// A rollout-mode change must produce a new slot version even when the
	// rules did not change: fold the mode into the version.
	bp.Version = bp.Version*4 + modeVersionBits(bp.Mode)

	return bp, nil
}

func modeVersionBits(m BuildPolicyMode) int {
	switch m {
	case BuildModeShadow:
		return 1
	case BuildModeEnforce:
		return 2
	default:
		return 0
	}
}

// Watch implements BuildPolicySource.
func (s *ProviderBuildPolicySource) Watch(fn func(projectPath string)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.next
	s.next++
	s.watchers[id] = fn

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.watchers, id)
	}
}

// Notify tells watchers that projectPath ("" = everything) changed.
// The owner of the underlying rule source calls it after a reload (CE:
// the YAML loader's reload hook; EE: the rule watcher / policycache
// update callback).
func (s *ProviderBuildPolicySource) Notify(projectPath string) {
	s.mu.Lock()

	fns := make([]func(string), 0, len(s.watchers))
	for _, fn := range s.watchers {
		fns = append(fns, fn)
	}

	s.mu.Unlock()

	for _, fn := range fns {
		fn(projectPath)
	}
}
