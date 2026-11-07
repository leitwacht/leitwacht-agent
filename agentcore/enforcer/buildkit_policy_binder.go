package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PolicyKey names the policy a build step is judged by: the claimed
// project and (possibly empty = project default) job name.
type PolicyKey struct {
	Project string
	Job     string
}

func (k PolicyKey) String() string {
	return k.Project + "/" + k.Job
}

// Binding strengths: how a RUN cgroup was tied to its candidate(s).
const (
	StrengthExactArgv       = "exact_argv"
	StrengthEnvironTiebreak = "environ_tiebreak"
	StrengthWeakTail        = "weak_tail"
	StrengthSessionLevel    = "session_level"
	StrengthAmbiguous       = "ambiguous"
)

// JoinOutcome is how a cgroup's join attempt ended without a link.
type JoinOutcome string

const (
	// JoinDeadline: no pending vertex matched before the join deadline.
	JoinDeadline JoinOutcome = "deadline"
	// JoinHistoryDown: the history watcher was disconnected, so the
	// registry could not be trusted to know the owning session.
	JoinHistoryDown JoinOutcome = "history_down"
)

// BindingObserver is told about every change to a RUN cgroup's join
// result. The BuildPolicyBinder implements it.
type BindingObserver interface {
	OnBind(cgroupID uint64, b CgroupBinding)
	OnUnbind(cgroupID uint64)
	OnJoinOutcome(cgroupID uint64, cgroupPath string, o JoinOutcome)
	OnSessionRegistered(attrs map[string]string)
}

const (
	// slotIdleGrace is how long a slot with no bound cgroups stays
	// installed, so back-to-back RUN steps of one build reuse it and an
	// in-flight policy flip can drain.
	slotIdleGrace = 2 * time.Minute

	// policyFetchTimeout bounds a synchronous policy fetch on the join
	// path. Prefetch at session registration makes this the cold case.
	policyFetchTimeout = time.Second

	policyErrTTL = 10 * time.Second

	runLevelWarnInterval = 30 * time.Second
)

type slotKey struct {
	Project string
	Job     string
	Version int
}

type slotState struct {
	idx       uint32
	key       slotKey
	policy    BuildPolicy
	refs      int
	idleSince time.Time
}

// cgDecision is the binder's immutable verdict for one RUN cgroup.
type cgDecision struct {
	state     uint8
	mode      uint8
	strength  string
	key       PolicyKey
	mixedJobs bool
	// reason is the enforcement-state string for non-bound decisions
	// (ambiguous_multi_project, unattributed, degraded_*,
	// policy_unavailable) and the degraded reason for DEGRADED ones.
	reason string
	// policy is the bound policy (nil unless state==bound), kept so
	// pre-bind rows can be evaluated against it after the cgroup is gone.
	policy   *BuildPolicy
	slot     *slotState
	gen      uint32
	boundAt  time.Time
	policyID string // project@version/job

	// path is the cgroup directory the decision was made for (sweep
	// checks it still names this cgroup).
	path string
	// fromRegistry marks decisions backed by a registry binding.
	fromRegistry bool
	// fqdnInactive: the bound policy has name rules the datapath does not
	// enforce yet (no build DNS proxy), only its IP rules apply.
	fqdnInactive bool
}

type retiredDecision struct {
	dec       *cgDecision
	retiredAt time.Time
}

type cachedPolicy struct {
	pol BuildPolicy
	err error
	at  time.Time
}

// BuildPolicyBinder turns join results into datapath state: it decides
// which policy (if any) a RUN cgroup runs under, installs refcounted
// slots, writes the per-cgroup entries and later annotates reported rows
// with the outcome.
//
// The rules:
//  1. an exact single argv link with a routable claim binds to the
//     claimed (project, job);
//  2. any candidate set sharing one (project, job) binds to it;
//  3. candidates of one project but different jobs bind to the project
//     default list, flagged mixed;
//  4. candidates across projects, an unroutable claim or none at all:
//     audit (ambiguous / unattributed), never enforcement;
//  5. no policy, not enrolled, audit action: audit.
//
// argv and environ are forgeable, so neither environ tiebreak nor tail
// evidence ever chooses between different projects: such cgroups carry
// every candidate in CandidateKeys and rule 4 applies.
type BuildPolicyBinder struct {
	src      BuildPolicySource
	dp       BuildKitDatapath
	log      *slog.Logger
	now      func() time.Time
	maxSlots int
	grace    time.Duration
	trusted  []net.IPNet

	historyDown func() bool
	sessions    SessionsLookup

	mu       sync.Mutex
	slots    map[slotKey]*slotState
	free     []uint32
	cgs      map[uint64]*cgDecision
	retired  map[uint64]retiredDecision
	policies map[PolicyKey]cachedPolicy

	cancelWatch func()

	// epoch counts policy changes; a bind that fetched its policy in an
	// older epoch refetches instead of installing a stale version.
	epoch uint64

	// current/statFn verify, under mu, that the cgroup a bind is for is
	// still the registry's live binding and still exists.
	current func(id uint64) (CgroupBinding, bool)
	statFn  func(path string) (uint64, error)

	dnsUpstreams []net.IP
	fqdnLogged   map[slotKey]bool

	// Pre-bind SYN hold: the datapath flag follows "is any enforce
	// policy in play". enforceSeen records when a session registration
	// last prefetched an enforce-mode policy for a key (covers the gap
	// before the session is visible in the session lookup).
	holdMu      sync.Mutex
	holdOn      bool
	enforceSeen map[PolicyKey]time.Time

	// capacityEvents counts cgroups left in audit for lack of slot or
	// map capacity; surfaced through Stats.
	capacityEvents atomic.Int64
	lastRunWarn    atomic.Int64
}

// BinderOption tunes a BuildPolicyBinder.
type BinderOption func(*BuildPolicyBinder)

// WithBinderClock overrides the clock (tests).
func WithBinderClock(now func() time.Time) BinderOption {
	return func(b *BuildPolicyBinder) { b.now = now }
}

// WithBinderMaxSlots caps the slot count (default and maximum 256).
func WithBinderMaxSlots(n int) BinderOption {
	return func(b *BuildPolicyBinder) {
		if n > 0 && n <= bkMaxSlots {
			b.maxSlots = n
		}
	}
}

// WithBinderIdleGrace overrides the 2 minute slot idle grace (tests).
func WithBinderIdleGrace(d time.Duration) BinderOption {
	return func(b *BuildPolicyBinder) { b.grace = d }
}

// WithBinderTrustedCIDRs gives the binder the datapath's trusted
// networks so pre-bind evaluation matches the program.
func WithBinderTrustedCIDRs(c []net.IPNet) BinderOption {
	return func(b *BuildPolicyBinder) { b.trusted = c }
}

// WithBinderHistory supplies the history-reliability signals: whether
// the history watcher is down now, and the session set at a time.
func WithBinderHistory(down func() bool, sessions SessionsLookup) BinderOption {
	return func(b *BuildPolicyBinder) {
		b.historyDown = down
		b.sessions = sessions
	}
}

// WithBinderCgroupCheck gives the binder the registry's live-binding
// lookup and a cgroup-path stat (path -> cgroup id) so a bind racing a
// remove is dropped and the periodic sweep can reconcile.
func WithBinderCgroupCheck(current func(uint64) (CgroupBinding, bool), statFn func(string) (uint64, error)) BinderOption {
	return func(b *BuildPolicyBinder) {
		b.current = current
		b.statFn = statFn
	}
}

// WithBinderDNSUpstreams tells the binder the DNS upstreams the
// datapath's port-53 pin allows, so pre-bind evaluation matches.
func WithBinderDNSUpstreams(ips []net.IP) BinderOption {
	return func(b *BuildPolicyBinder) { b.dnsUpstreams = ips }
}

// NewBuildPolicyBinder returns a binder writing into dp. src may be nil
// (every cgroup then runs audit with policy_unavailable).
func NewBuildPolicyBinder(src BuildPolicySource, dp BuildKitDatapath, log *slog.Logger, opts ...BinderOption) *BuildPolicyBinder {
	if log == nil {
		log = slog.Default()
	}

	b := &BuildPolicyBinder{
		src:      src,
		dp:       dp,
		log:      log,
		now:      time.Now,
		maxSlots: bkMaxSlots,
		grace:    slotIdleGrace,
		slots:    map[slotKey]*slotState{},
		cgs:      map[uint64]*cgDecision{},
		retired:  map[uint64]retiredDecision{},
		policies: map[PolicyKey]cachedPolicy{},

		fqdnLogged:  map[slotKey]bool{},
		enforceSeen: map[PolicyKey]time.Time{},
	}

	for _, o := range opts {
		o(b)
	}

	for i := b.maxSlots - 1; i >= 0; i-- {
		b.free = append(b.free, uint32(i)) //nolint:gosec // i < 256
	}

	if src != nil {
		b.cancelWatch = src.Watch(b.OnPolicyChange)
	}

	return b
}

// Run drives slot GC until ctx is done.
func (b *BuildPolicyBinder) Run(ctx context.Context) {
	t := time.NewTicker(b.grace / 4)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Sweep()
			b.GC(b.now())
			b.RefreshHold()
		}
	}
}

// Close unregisters the policy watch. Datapath state is owned by the
// datapath and goes with it.
func (b *BuildPolicyBinder) Close() {
	if b.cancelWatch != nil {
		b.cancelWatch()
	}
}

// BinderStats is a point-in-time view for tests and logs.
type BinderStats struct {
	Slots          int
	FreeSlots      int
	BoundCgroups   int
	CapacityEvents int64
}

// Stats returns counters.
func (b *BuildPolicyBinder) Stats() BinderStats {
	b.mu.Lock()
	defer b.mu.Unlock()

	bound := 0

	for _, d := range b.cgs {
		if d.state == bkStateBound {
			bound++
		}
	}

	return BinderStats{Slots: len(b.slots), FreeSlots: len(b.free), BoundCgroups: bound, CapacityEvents: b.capacityEvents.Load()}
}

// bindOutcome is the pure classification of a binding (rules 1-4).
type bindOutcome struct {
	state     uint8
	key       PolicyKey
	strength  string
	mixedJobs bool
	reason    string // enforcement-state string when not bound
}

func keyFromAttrs(attrs map[string]string) PolicyKey {
	project, _, _, job, _, _, _ := CIOverrideFromFrontendAttrs(attrs)

	return PolicyKey{Project: project, Job: job}
}

// classify applies the binding rules to a join result. It never
// consults the policy: whether a bound key has an enforceable policy is
// a separate step.
func classify(b CgroupBinding) bindOutcome {
	// An argv match made while an unauthorized, placeholder or denied
	// session is open proves nothing about ownership (argv is forgeable):
	// audit, never a policy chosen by it.
	if b.Flag == BuildFlagArgvUntrusted {
		return bindOutcome{state: bkStateAmbiguous, strength: StrengthAmbiguous, reason: EnfStateAmbiguous}
	}

	keys := b.CandidateKeys

	strength := b.Strength

	if len(keys) == 0 && !b.Ambiguous && b.SessionRef != "" {
		keys = []PolicyKey{keyFromAttrs(b.FrontendAttrs)}

		if strength == "" {
			strength = StrengthExactArgv
		}
	}

	if strength == "" {
		strength = StrengthAmbiguous
	}

	uniq := uniqueKeys(keys)
	if len(uniq) == 0 {
		return bindOutcome{state: bkStateUnattributed, strength: strength, reason: EnfStateUnattributed}
	}

	projects := map[string]struct{}{}
	unroutable := false

	for _, k := range uniq {
		if k.Project == "" {
			unroutable = true

			continue
		}

		projects[k.Project] = struct{}{}
	}

	switch {
	case len(projects) == 0:
		// Every candidate lacks a project claim.
		return bindOutcome{state: bkStateUnattributed, strength: strength, reason: EnfStateUnattributed}
	case len(projects) > 1 || unroutable:
		// Across projects, or an unroutable candidate could be the real
		// owner: never enforce on a guess.
		return bindOutcome{state: bkStateAmbiguous, strength: StrengthAmbiguous, reason: EnfStateAmbiguous}
	}

	project := uniq[0].Project
	if len(uniq) == 1 {
		return bindOutcome{state: bkStateBound, key: uniq[0], strength: strength}
	}

	// One project, several job names: the project default list.
	return bindOutcome{
		state:     bkStateBound,
		key:       PolicyKey{Project: project},
		strength:  strength,
		mixedJobs: true,
	}
}

func uniqueKeys(in []PolicyKey) []PolicyKey {
	seen := map[PolicyKey]struct{}{}

	var out []PolicyKey

	for _, k := range in {
		if _, dup := seen[k]; dup {
			continue
		}

		seen[k] = struct{}{}
		out = append(out, k)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })

	return out
}

func modeByte(m BuildPolicyMode) uint8 {
	switch m {
	case BuildModeShadow:
		return bkModeShadow
	case BuildModeEnforce:
		return bkModeBlock
	default:
		return bkModeAudit
	}
}

// OnBind implements BindingObserver.
func (b *BuildPolicyBinder) OnBind(cgroupID uint64, bd CgroupBinding) {
	out := classify(bd)
	history := b.historyDown != nil && b.historyDown()

	const maxTries = 3

	for try := 0; try < maxTries; try++ {
		b.mu.Lock()
		epoch := b.epoch
		_, known := b.cgs[cgroupID]
		b.mu.Unlock()

		// New cgroups appearing while the history watcher is down cannot
		// be trusted to belong to a known session. Existing bound cgroups
		// keep their slot (this branch only judges first sight).
		degradedHistory := history && !known
		needPolicy := !degradedHistory && out.state == bkStateBound

		var (
			pol    BuildPolicy
			polErr error
		)

		if needPolicy {
			pol, polErr = b.fetch(out.key)
		}

		b.mu.Lock()

		if needPolicy && b.epoch != epoch && try < maxTries-1 {
			b.mu.Unlock()

			continue // the policy changed while fetching: refetch

		}

		if !b.stillCurrentLocked(cgroupID, bd) {
			// Unbound or removed while the policy was being fetched.
			b.mu.Unlock()

			return
		}

		switch {
		case degradedHistory:
			b.applyNonBoundLocked(cgroupID, bd, bkStateDegraded, EnfStateDegradedHist, out.strength, out.key)
		case out.state != bkStateBound:
			b.applyNonBoundLocked(cgroupID, bd, out.state, out.reason, out.strength, out.key)
		case polErr != nil:
			b.applyNonBoundLocked(cgroupID, bd, bkStateDegraded, EnfStatePolicyUnavl, out.strength, out.key)
		default:
			b.applyBoundLocked(cgroupID, bd, out, pol)
		}

		b.mu.Unlock()

		return
	}
}

// stillCurrentLocked reports whether the cgroup a bind was made for is
// still the registry's live binding and still exists. Without the check a
// remove that ran OnUnbind while the policy was being fetched would leave
// the late bind installed forever.
func (b *BuildPolicyBinder) stillCurrentLocked(id uint64, bd CgroupBinding) bool {
	if !bd.LinkedAt.IsZero() && b.current != nil {
		cur, ok := b.current(id)
		if !ok || !cur.LinkedAt.Equal(bd.LinkedAt) {
			return false
		}
	}

	if bd.CgroupPath != "" && b.statFn != nil {
		got, err := b.statFn(bd.CgroupPath)
		if err != nil && errors.Is(err, os.ErrNotExist) {
			return false
		}

		if err == nil && got != id {
			return false
		}
	}

	return true
}

// Sweep reconciles decisions against the registry and the filesystem:
// a decision whose cgroup is gone (or whose registry binding vanished)
// without an unbind having reached us is released.
func (b *BuildPolicyBinder) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for id, d := range b.cgs {
		gone := false

		if d.fromRegistry && b.current != nil {
			if _, ok := b.current(id); !ok {
				gone = true
			}
		}

		if !gone && d.path != "" && b.statFn != nil {
			got, err := b.statFn(d.path)
			if (err != nil && errors.Is(err, os.ErrNotExist)) || (err == nil && got != id) {
				gone = true
			}
		}

		if gone {
			b.dropLocked(id, true)
		}
	}
}

// OnJoinOutcome implements BindingObserver: a cgroup whose join ended
// without a link. History trouble degrades it; otherwise a final
// session-level candidate set (every session open at the deadline) is
// bound by the same rules, so a lone open build still gets its policy
// while overlapping builds of different projects stay audit.
func (b *BuildPolicyBinder) OnJoinOutcome(cgroupID uint64, cgroupPath string, o JoinOutcome) {
	b.mu.Lock()
	_, known := b.cgs[cgroupID]
	b.mu.Unlock()

	if known {
		return
	}

	synthetic := CgroupBinding{CgroupPath: cgroupPath, Ambiguous: true, Strength: StrengthSessionLevel}

	if o == JoinHistoryDown || (b.historyDown != nil && b.historyDown()) {
		synthetic.Strength = StrengthAmbiguous
		b.commitNonBound(cgroupID, synthetic, bkStateDegraded, EnfStateDegradedHist, StrengthAmbiguous)

		return
	}

	if b.sessions == nil {
		b.commitNonBound(cgroupID, synthetic, bkStateUnattributed, EnfStateUnattributed, StrengthAmbiguous)

		return
	}

	now := b.now()

	cands, reliable := b.sessions(now)
	if !reliable {
		b.commitNonBound(cgroupID, synthetic, bkStateDegraded, EnfStateDegradedHist, StrengthAmbiguous)

		return
	}

	open := activeSessionsAt(cands, now)

	keys := make([]PolicyKey, 0, len(open))
	for _, s := range open {
		if s.Completed {
			continue
		}

		keys = append(keys, keyFromAttrs(s.FrontendAttrs))
	}

	synthetic.CandidateKeys = keys

	b.OnBind(cgroupID, synthetic)
}

func (b *BuildPolicyBinder) commitNonBound(id uint64, bd CgroupBinding, state uint8, reason, strength string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.stillCurrentLocked(id, bd) {
		return
	}

	b.applyNonBoundLocked(id, bd, state, reason, strength, PolicyKey{})
}

// OnSessionRegistered implements BindingObserver: warm the policy cache
// for the claimed project so linking is a map write.
func (b *BuildPolicyBinder) OnSessionRegistered(attrs map[string]string) {
	k := keyFromAttrs(attrs)
	if k.Project == "" || b.src == nil {
		return
	}

	go func() {
		pol, err := b.fetch(k)
		if err == nil && pol.Mode == BuildModeEnforce {
			b.holdMu.Lock()
			b.enforceSeen[k] = b.now()
			b.holdMu.Unlock()
		}

		b.RefreshHold()
	}()
}

// holdSeenTTL is how long a prefetched enforce policy keeps the SYN hold
// on without the session being visible in the session lookup.
const holdSeenTTL = time.Minute

// RefreshHold sets the datapath's pre-bind SYN hold: on while a bound
// cgroup is in enforce, or an open session's cached policy is enforce,
// or an enforce policy was prefetched in the last minute. Audit/shadow
// only clusters never pay the hold latency. Idempotent; safe to call
// often.
func (b *BuildPolicyBinder) RefreshHold() {
	if b.dp == nil {
		return
	}

	now := b.now()
	want := false
	enforceKeys := map[PolicyKey]bool{}

	b.mu.Lock()

	for _, d := range b.cgs {
		if d.state == bkStateBound && d.mode == bkModeBlock {
			want = true

			break
		}
	}

	for k, c := range b.policies {
		if c.err == nil && c.pol.Mode == BuildModeEnforce {
			enforceKeys[k] = true
		}
	}

	b.mu.Unlock()

	if !want {
		b.holdMu.Lock()
		for k, at := range b.enforceSeen {
			if now.Sub(at) < holdSeenTTL {
				want = true
			} else {
				delete(b.enforceSeen, k)
			}
		}
		b.holdMu.Unlock()
	}

	if !want && len(enforceKeys) > 0 && b.sessions != nil {
		cands, _ := b.sessions(now)

		for _, s := range activeSessionsAt(cands, now) {
			if !s.Completed && enforceKeys[keyFromAttrs(s.FrontendAttrs)] {
				want = true

				break
			}
		}
	}

	b.holdMu.Lock()
	defer b.holdMu.Unlock()

	if want == b.holdOn {
		return
	}

	if err := b.dp.SetHold(want); err != nil {
		b.log.Warn("buildkit policy: cannot set pre-bind SYN hold", "enabled", want, "error", err)

		return
	}

	b.holdOn = want
	b.log.Info("buildkit pre-bind SYN hold", "enabled", want)
}

// OnUnbind implements BindingObserver.
func (b *BuildPolicyBinder) OnUnbind(cgroupID uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.dropLocked(cgroupID, true)
}

// fetch returns the policy for key, from cache when fresh. A result
// fetched across a policy change is returned but not cached.
func (b *BuildPolicyBinder) fetch(key PolicyKey) (BuildPolicy, error) {
	if b.src == nil {
		return BuildPolicy{}, ErrBuildPolicyUnavailable
	}

	b.mu.Lock()

	if c, ok := b.policies[key]; ok && (c.err == nil || b.now().Sub(c.at) < policyErrTTL) {
		b.mu.Unlock()

		return c.pol, c.err
	}

	epoch := b.epoch

	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), policyFetchTimeout)
	defer cancel()

	pol, err := b.src.Policy(ctx, key.Project, key.Job)
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrBuildPolicyUnavailable, err)
	}

	b.mu.Lock()
	if b.epoch == epoch {
		b.policies[key] = cachedPolicy{pol: pol, err: err, at: b.now()}
	}
	b.mu.Unlock()

	return pol, err
}

// commitLocked writes id's kernel entry and swaps its decision. The old
// slot reference is kept until the write succeeded. On failure the entry
// is deleted (the cgroup falls back to PENDING, which is audit), the new
// slot reference is released and the cgroup is recorded as degraded
// capacity: a failed write must never leave the cgroup on a slot nobody
// accounts for, nor on a stale entry.
func (b *BuildPolicyBinder) commitLocked(id uint64, nd *cgDecision, entry BKCgroupPolicy) {
	old := b.cgs[id]

	if err := b.dp.SetCgroupPolicy(id, entry); err != nil {
		b.capacityEvents.Add(1)
		b.log.Warn("buildkit policy: cannot write cgroup entry; cgroup falls back to audit",
			"cgroup_id", id, "policy_key", nd.key.String(), "error", err)

		if delErr := b.dp.DeleteCgroupPolicy(id); delErr != nil {
			b.log.Warn("buildkit policy: cannot delete cgroup entry", "cgroup_id", id, "error", delErr)
		}

		b.releaseLocked(nd.slot)

		nd = &cgDecision{
			state: bkStateDegraded, mode: bkModeAudit, strength: nd.strength, key: nd.key,
			reason: EnfStateDegradedCap, boundAt: b.now(), path: nd.path, fromRegistry: nd.fromRegistry,
		}
	}

	b.cgs[id] = nd

	if old != nil {
		b.releaseLocked(old.slot)
	}
}

// applyNonBoundLocked records an audit decision and writes the entry so
// events carry the right state.
func (b *BuildPolicyBinder) applyNonBoundLocked(
	id uint64, bd CgroupBinding, state uint8, reason, strength string, key PolicyKey,
) {
	b.commitLocked(id, &cgDecision{
		state:        state,
		mode:         bkModeAudit,
		strength:     strength,
		key:          key,
		reason:       reason,
		boundAt:      b.now(),
		path:         bd.CgroupPath,
		fromRegistry: !bd.LinkedAt.IsZero(),
	}, BKCgroupPolicy{State: state, Mode: bkModeAudit})
}

// applyBoundLocked installs/reuses the slot for (key, version) and binds
// the cgroup to it. Capacity problems leave the cgroup in audit.
func (b *BuildPolicyBinder) applyBoundLocked(id uint64, bd CgroupBinding, out bindOutcome, pol BuildPolicy) {
	slot, err := b.acquireLocked(out.key, pol)
	if err != nil {
		b.capacityEvents.Add(1)
		b.log.Warn("buildkit policy: no slot capacity; cgroup stays in audit",
			"cgroup_id", id, "policy_key", out.key.String(), "error", err)

		b.applyNonBoundLocked(id, bd, bkStateDegraded, EnfStateDegradedCap, out.strength, out.key)

		return
	}

	dec := &cgDecision{
		state:        bkStateBound,
		mode:         modeByte(slot.policy.Mode),
		strength:     out.strength,
		key:          out.key,
		mixedJobs:    out.mixedJobs,
		policy:       &slot.policy,
		slot:         slot,
		gen:          1,
		boundAt:      b.now(),
		policyID:     policyID(out.key, slot.policy.Version),
		path:         bd.CgroupPath,
		fromRegistry: !bd.LinkedAt.IsZero(),
		fqdnInactive: b.noteFQDNLocked(slot),
	}

	if old := b.cgs[id]; old != nil && old.gen > 0 && old.slot == slot {
		dec.gen = old.gen + 1
	}

	b.commitLocked(id, dec, BKCgroupPolicy{Slot: slot.idx, State: bkStateBound, Mode: dec.mode, Gen: dec.gen})

	if b.cgs[id] == dec {
		b.log.Info("buildkit cgroup bound to policy",
			"cgroup_id", id,
			"policy_key", dec.policyID,
			"mode", slot.policy.Mode,
			"strength", out.strength,
			"mixed_jobs", out.mixedJobs,
		)
	}
}

// noteFQDNLocked reports (and logs once per slot version) that the
// slot's policy has name rules the datapath does not enforce yet.
func (b *BuildPolicyBinder) noteFQDNLocked(s *slotState) bool {
	if s.policy.Mode == BuildModeAudit {
		return false
	}

	has := false

	for _, r := range s.policy.FQDNRules {
		if r.Allow {
			has = true

			break
		}
	}

	if !has {
		return false
	}

	if !b.fqdnLogged[s.key] {
		b.fqdnLogged[s.key] = true

		lvl := slog.LevelWarn
		if s.policy.Mode == BuildModeEnforce {
			lvl = slog.LevelError
		}

		b.log.Log(context.Background(), lvl,
			"buildkit policy: domain rules not yet enforced for build steps; only IP rules apply",
			"policy_key", policyID(PolicyKey{Project: s.key.Project, Job: s.key.Job}, s.key.Version),
			"mode", s.policy.Mode)
	}

	return true
}

func policyID(k PolicyKey, version int) string {
	return fmt.Sprintf("%s@%d/%s", k.Project, version, k.Job)
}

var errNoFreeSlot = errors.New("no free policy slot")

// acquireLocked returns the slot for (key, pol.Version), installing it
// if needed, and takes a reference.
func (b *BuildPolicyBinder) acquireLocked(key PolicyKey, pol BuildPolicy) (*slotState, error) {
	sk := slotKey{Project: key.Project, Job: key.Job, Version: pol.Version}

	if s, ok := b.slots[sk]; ok {
		s.refs++
		s.idleSince = time.Time{}

		return s, nil
	}

	if len(b.free) == 0 {
		return nil, errNoFreeSlot
	}

	idx := b.free[len(b.free)-1]

	var rules BKSlotRules

	for _, r := range pol.IPRules {
		if r.Allow {
			rules.Allow = append(rules.Allow, r)
		} else {
			rules.Deny = append(rules.Deny, r)
		}
	}

	if err := b.dp.InstallSlot(idx, rules); err != nil {
		return nil, fmt.Errorf("install slot: %w", err)
	}

	b.free = b.free[:len(b.free)-1]

	s := &slotState{idx: idx, key: sk, policy: pol, refs: 1}
	b.slots[sk] = s

	return s, nil
}

func (b *BuildPolicyBinder) releaseLocked(s *slotState) {
	if s == nil {
		return
	}

	s.refs--
	if s.refs <= 0 {
		s.refs = 0
		s.idleSince = b.now()
	}
}

// dropLocked forgets a cgroup's decision. unbind=true also deletes the
// kernel entry and retires the decision for flush-time lookups.
func (b *BuildPolicyBinder) dropLocked(id uint64, unbind bool) {
	dec, ok := b.cgs[id]
	if !ok {
		return
	}

	delete(b.cgs, id)
	b.releaseLocked(dec.slot)

	if !unbind {
		return
	}

	if err := b.dp.DeleteCgroupPolicy(id); err != nil {
		b.log.Debug("buildkit policy: delete cgroup entry", "cgroup_id", id, "error", err)
	}

	now := b.now()

	if len(b.retired) >= maxRetired {
		for k, v := range b.retired {
			if now.Sub(v.retiredAt) > retiredRetention || len(b.retired) >= maxRetired {
				delete(b.retired, k)
			}
		}
	}

	b.retired[id] = retiredDecision{dec: dec, retiredAt: now}
}

// GC frees slots idle for longer than the grace.
func (b *BuildPolicyBinder) GC(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for sk, s := range b.slots {
		if s.refs > 0 || s.idleSince.IsZero() || now.Sub(s.idleSince) < b.grace {
			continue
		}

		if err := b.dp.RemoveSlot(s.idx); err != nil {
			b.log.Warn("buildkit policy: remove slot", "slot", s.idx, "error", err)

			continue
		}

		delete(b.slots, sk)
		b.free = append(b.free, s.idx)
	}

	for id, r := range b.retired {
		if now.Sub(r.retiredAt) > retiredRetention {
			delete(b.retired, id)
		}
	}

	for k, c := range b.policies {
		if c.err != nil && now.Sub(c.at) >= policyErrTTL {
			delete(b.policies, k)
		}
	}
}

// OnPolicyChange refreshes slots after a policy change for project
// ("" = all). New inner maps are built into a new slot, then every
// bound cgroup is flipped (per-cgroup atomic). A mode-only change flips
// just the mode. The old slot drains through the idle grace.
func (b *BuildPolicyBinder) OnPolicyChange(project string) {
	b.mu.Lock()

	b.epoch++

	var keys []PolicyKey

	for k := range b.policies {
		if project == "" || k.Project == project {
			delete(b.policies, k)
		}
	}

	seen := map[PolicyKey]struct{}{}

	for _, s := range b.slots {
		if s.refs == 0 || (project != "" && s.key.Project != project) {
			continue
		}

		pk := PolicyKey{Project: s.key.Project, Job: s.key.Job}
		if _, dup := seen[pk]; !dup {
			seen[pk] = struct{}{}
			keys = append(keys, pk)
		}
	}

	b.mu.Unlock()

	for _, k := range keys {
		pol, err := b.fetch(k)
		if err != nil {
			// Keep running the policy already installed: a fetch failure
			// is not a reason to change enforcement mid-build.
			b.log.Warn("buildkit policy: refresh failed; keeping installed policy", "policy_key", k.String(), "error", err)

			continue
		}

		b.flip(k, pol)
	}
}

func (b *BuildPolicyBinder) flip(k PolicyKey, pol BuildPolicy) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var target *slotState

	for id, dec := range b.cgs {
		if dec.state != bkStateBound || dec.slot == nil || dec.slot.key.Project != k.Project || dec.slot.key.Job != k.Job {
			continue
		}

		if dec.slot.key.Version == pol.Version {
			// Same rules; only the mode can differ.
			if dec.mode == modeByte(pol.Mode) {
				continue
			}

			dec.slot.policy.Mode = pol.Mode

			b.writeFlipLocked(id, dec, dec.slot)

			continue
		}

		if target == nil {
			s, err := b.acquireLocked(k, pol)
			if err != nil {
				b.capacityEvents.Add(1)
				b.log.Warn("buildkit policy: no capacity for updated policy; keeping previous",
					"policy_key", k.String(), "error", err)

				return
			}

			// acquireLocked took one reference; the per-cgroup flips below
			// take their own, so drop this one afterwards.
			target = s
		}

		target.refs++
		b.writeFlipLocked(id, dec, target)
	}

	if target != nil {
		b.releaseLocked(target)
	}
}

// writeFlipLocked points cgroup id at slot s (bumping gen) and swaps the
// decision. On a write error the cgroup keeps its previous slot.
func (b *BuildPolicyBinder) writeFlipLocked(id uint64, dec *cgDecision, s *slotState) {
	nd := *dec
	nd.slot = s
	nd.policy = &s.policy
	nd.mode = modeByte(s.policy.Mode)
	nd.gen = dec.gen + 1
	nd.policyID = policyID(dec.key, s.policy.Version)
	nd.fqdnInactive = b.noteFQDNLocked(s)

	err := b.dp.SetCgroupPolicy(id, BKCgroupPolicy{Slot: s.idx, State: bkStateBound, Mode: nd.mode, Gen: nd.gen})
	if err != nil {
		if s != dec.slot {
			b.releaseLocked(s)
		}

		b.log.Warn("buildkit policy: flip failed; cgroup keeps previous policy", "cgroup_id", id, "error", err)

		return
	}

	if s != dec.slot {
		b.releaseLocked(dec.slot)
	}

	b.cgs[id] = &nd
}

// decisionFor returns the live decision for a cgroup, else the retired
// one when the row's time is within the id-reuse grace of retirement.
func (b *BuildPolicyBinder) decisionFor(id uint64, at time.Time) (*cgDecision, bool) {
	if d, ok := b.cgs[id]; ok {
		return d, true
	}

	if r, ok := b.retired[id]; ok && !at.After(r.retiredAt.Add(retiredIDReuseGrace)) {
		return r.dec, true
	}

	return nil, false
}

// Annotate stamps enforcement context on rows at flush time: strength,
// policy key, state, degraded reason, and for rows that passed
// un-enforced before binding, whether the bound policy would deny.
func (b *BuildPolicyBinder) Annotate(violations []Violation) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range violations {
		v := &violations[i]
		if v.CgroupID == 0 {
			continue
		}

		dec, ok := b.decisionFor(v.CgroupID, v.Timestamp)
		if !ok {
			continue
		}

		b.annotateLocked(v, dec)
	}
}

func (b *BuildPolicyBinder) annotateLocked(v *Violation, dec *cgDecision) {
	v.BindingStrength = dec.strength
	v.BindingVerified = false

	if dec.policyID != "" {
		v.PolicyKey = dec.policyID
	}

	if dec.state != bkStateBound {
		v.DegradedReason = degradedReasonFor(dec.reason)
	} else if dec.fqdnInactive && v.DegradedReason == "" {
		v.DegradedReason = DegradedFQDNInactive
	}

	if dec.reason == EnfStateDegradedHist && v.BuildFlag == "" {
		v.BuildFlag = BuildFlagHistoryDisconnected
	}

	if v.EnforcementState == EnfStateDegradedLevel {
		return
	}

	if v.EnforcementState == EnfStatePendingBind {
		// Recorded before the cgroup had an entry, so nothing was
		// enforced. Evaluate what the bound policy would have done.
		if dec.state == bkStateBound && dec.policy != nil && dec.policy.Mode != BuildModeAudit &&
			wouldDeny(dec.policy, v.IP, v.Port, b.trusted, b.dnsUpstreams) {
			v.WouldBlock = true
		}

		return
	}

	v.EnforcementState = enforcementStateFor(v.Action, dec)
}

// Degraded reasons that are not enforcement states.
const (
	DegradedFQDNInactive = "fqdn_rules_inactive"
	DegradedRunLevel     = "run_level_mismatch"
)

func degradedReasonFor(reason string) string {
	switch reason {
	case EnfStateDegradedCap, EnfStateDegradedHist, EnfStatePolicyUnavl:
		return reason
	default:
		return ""
	}
}

func enforcementStateFor(action string, dec *cgDecision) string {
	switch action {
	case "packet_dropped", "sinkhole_hit", "dns_bypass_dropped":
		return EnfStateEnforced
	case "would_block":
		return EnfStateShadow
	}

	if dec.state == bkStateBound {
		// Every verdict of a bound cgroup (allowed, observed, ...) takes
		// the state of the slot's mode; audit_project is for genuinely
		// audit slots only.
		switch dec.mode {
		case bkModeBlock:
			return EnfStateEnforced
		case bkModeShadow:
			return EnfStateShadow
		}

		return EnfStateAuditProject
	}

	return dec.reason
}

// FinalizeUnbound sets the enforcement state of rows that never got a
// decision: still pending_bind rows flagged unattributed become
// unattributed.
func FinalizeUnbound(violations []Violation) {
	for i := range violations {
		v := &violations[i]
		if v.EnforcementState != EnfStatePendingBind {
			continue
		}

		switch {
		case v.BuildAmbiguous:
			v.EnforcementState = EnfStateAmbiguous
		case v.BuildUnattributed:
			v.EnforcementState = EnfStateUnattributed
		}
	}
}

// wouldDeny reports whether the datapath would deny ip:port under pol,
// mirroring egress_bk.h: invariants first, then ordered rules (deny wins
// ties), then trusted networks, then default deny. DNS-derived allows
// are not known here.
func wouldDeny(pol *BuildPolicy, ipStr string, port int, trusted []net.IPNet, dns []net.IP) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}

	if isHardBlocked(ip, port) {
		return true
	}

	if ip[0] == 127 || (ip[0] == 169 && ip[1] == 254) {
		return false
	}

	// DNS pin: port 53 only to the configured upstream(s).
	if port == 53 && len(dns) > 0 {
		for _, d := range dns {
			if d.Equal(ip) {
				return false
			}
		}

		return true
	}

	deny, allow := ^uint32(0), ^uint32(0)

	for _, r := range pol.IPRules {
		if r.IP != ip.String() || (r.Port != port && r.Port != 0) {
			continue
		}

		if r.Allow {
			allow = min(allow, r.Prio)
		} else {
			deny = min(deny, r.Prio)
		}
	}

	if deny != ^uint32(0) && deny <= allow {
		return true
	}

	if allow != ^uint32(0) {
		return false
	}

	for i := range trusted {
		if trusted[i].Contains(ip) {
			return false
		}
	}

	return true
}

func isHardBlocked(ip net.IP, port int) bool {
	if port == 853 { // DoT
		return true
	}

	switch ip.String() {
	case "169.254.169.254", "169.254.170.2", "169.254.170.23", "100.100.100.200", "169.254.0.23", "192.0.2.1":
		return true
	}

	return false
}

// bkEventStateHook receives (cgroup id, kernel state) for every egress_bk
// event, so a wrong run_level (events for a bound cgroup that still see no
// policy entry) is loud instead of silently auditing.
//
//nolint:gochecknoglobals // package-level hook, same rationale as buildKitLookup.
var bkEventStateHook atomic.Pointer[func(uint64, uint8)]

func noteBKEventState(id uint64, state uint8) {
	if fn := bkEventStateHook.Load(); fn != nil {
		(*fn)(id, state)
	}
}

// NoteEvent flags the run_level misconfiguration symptom.
func (b *BuildPolicyBinder) NoteEvent(id uint64, state uint8) {
	if state == bkStateDegradedLevel {
		last := b.lastRunWarn.Load()
		if b.now().UnixNano()-last >= int64(runLevelWarnInterval) && b.lastRunWarn.CompareAndSwap(last, b.now().UnixNano()) {
			b.log.Error("buildkit policy: egress from a cgroup under no configured BuildKit parent; "+
				"the cgroup layout does not match the configured paths, build steps run in audit",
				"cgroup_id", id)
		}

		return
	}

	if state != bkStatePending {
		return
	}

	b.mu.Lock()
	dec, ok := b.cgs[id]
	b.mu.Unlock()

	if !ok || dec.state != bkStateBound || b.now().Sub(dec.boundAt) < 2*time.Second {
		return
	}

	last := b.lastRunWarn.Load()
	if b.now().UnixNano()-last < int64(runLevelWarnInterval) || !b.lastRunWarn.CompareAndSwap(last, b.now().UnixNano()) {
		return
	}

	b.log.Warn("buildkit policy: egress event for a bound cgroup saw no policy entry; the cgroup entry may not have been written",
		"cgroup_id", id)
}

// InstallEventHook registers b for NoteEvent; the returned func removes
// it (only if still b's).
func (b *BuildPolicyBinder) InstallEventHook() func() {
	fn := b.NoteEvent
	bkEventStateHook.Store(&fn)

	return func() { bkEventStateHook.CompareAndSwap(&fn, nil) }
}
