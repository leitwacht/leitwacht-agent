package enforcer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// ---- fakes ----

type fakeDP struct {
	mu        sync.Mutex
	slots     map[uint32]BKSlotRules
	cgs       map[uint64]BKCgroupPolicy
	installs  int
	removed   []uint32
	failSlots bool
	failCgs   bool

	hold      bool
	holdCalls int

	cfg       BKConfig
	attached  []string
	ring      func(uint64) *ViolationRecorder
	ancestors map[uint64]int
	closed    bool
}

func newFakeDP() *fakeDP {
	return &fakeDP{slots: map[uint32]BKSlotRules{}, cgs: map[uint64]BKCgroupPolicy{}}
}

func (f *fakeDP) AttachCgroup(p string) (CgroupLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.attached = append(f.attached, p)

	return fakeLink{}, nil
}

func (f *fakeDP) SetConfig(c BKConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cfg = c

	return nil
}

func (f *fakeDP) SetHold(on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.hold = on
	f.holdCalls++

	return nil
}

func (f *fakeDP) AddSockKnownAncestor(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.ancestors == nil {
		f.ancestors = map[uint64]int{}
	}

	f.ancestors[id]++

	return nil
}

func (f *fakeDP) RemoveSockKnownAncestor(id uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ancestors[id]--
}

func (f *fakeDP) InstallSlot(slot uint32, r BKSlotRules) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failSlots {
		return errors.New("E2BIG") //nolint:err113 // test fake
	}

	f.installs++
	f.slots[slot] = r

	return nil
}

func (f *fakeDP) RemoveSlot(slot uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.slots, slot)
	f.removed = append(f.removed, slot)

	return nil
}

func (f *fakeDP) SetCgroupPolicy(id uint64, p BKCgroupPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failCgs {
		return errors.New("table full") //nolint:err113 // test fake
	}

	f.cgs[id] = p

	return nil
}

func (f *fakeDP) DeleteCgroupPolicy(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.cgs, id)

	return nil
}

func (f *fakeDP) StartRingbufReader(_ context.Context, lookup func(uint64) *ViolationRecorder) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ring = lookup

	return func() {}, nil
}

func (f *fakeDP) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed = true

	return nil
}

func (f *fakeDP) cg(id uint64) (BKCgroupPolicy, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	p, ok := f.cgs[id]

	return p, ok
}

type fakeLink struct{}

func (fakeLink) Close() error { return nil }

type fakeSource struct {
	mu       sync.Mutex
	pols     map[PolicyKey]BuildPolicy
	fetches  int
	watchers []func(string)
}

func newFakeSource() *fakeSource { return &fakeSource{pols: map[PolicyKey]BuildPolicy{}} }

func (s *fakeSource) set(project, job string, p BuildPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.ProjectPath, p.JobName = project, job
	s.pols[PolicyKey{project, job}] = p
}

func (s *fakeSource) Policy(_ context.Context, project, job string) (BuildPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fetches++

	if p, ok := s.pols[PolicyKey{project, job}]; ok {
		return p, nil
	}

	if p, ok := s.pols[PolicyKey{project, ""}]; ok {
		return p, nil
	}

	return BuildPolicy{}, ErrBuildPolicyUnavailable
}

func (s *fakeSource) Watch(fn func(string)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.watchers = append(s.watchers, fn)

	return func() {}
}

func (s *fakeSource) notify(project string) {
	s.mu.Lock()
	ws := append([]func(string){}, s.watchers...)
	s.mu.Unlock()

	for _, w := range ws {
		w(project)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func enforcePol(version int, ip string) BuildPolicy {
	return BuildPolicy{
		Mode:    BuildModeEnforce,
		Version: version,
		IPRules: []BuildIPRule{{IP: ip, Port: 443, Allow: true, Prio: policy.RulePriority(0)}},
	}
}

func exactBinding(project, job string) CgroupBinding {
	return CgroupBinding{
		SessionRef: "r-" + project + job,
		FrontendAttrs: map[string]string{
			FrontendAttrKeyProjectPath: project,
			FrontendAttrKeyJobName:     job,
		},
		Strength:      StrengthExactArgv,
		CandidateKeys: []PolicyKey{{project, job}},
	}
}

func ambiguousBinding(strength string, keys ...PolicyKey) CgroupBinding {
	return CgroupBinding{Ambiguous: true, Strength: strength, CandidateKeys: keys}
}

type binderRig struct {
	b   *BuildPolicyBinder
	dp  *fakeDP
	src *fakeSource
	clk *fakeClock
}

func newRig(opts ...BinderOption) *binderRig {
	r := &binderRig{dp: newFakeDP(), src: newFakeSource(), clk: &fakeClock{t: time.Unix(1_000_000, 0)}}
	opts = append([]BinderOption{WithBinderClock(r.clk.now)}, opts...)
	r.b = NewBuildPolicyBinder(r.src, r.dp, quietLog(), opts...)

	return r
}

// ---- classification (binding rules) ----

func TestClassify_Rules(t *testing.T) {
	t.Parallel()

	a1, a2 := PolicyKey{"g/a", "build"}, PolicyKey{"g/a", "test"}
	b1 := PolicyKey{"g/b", "build"}

	cases := []struct {
		name      string
		bind      CgroupBinding
		state     uint8
		key       PolicyKey
		mixed     bool
		strength  string
		enfReason string
	}{
		{"exact single link", exactBinding("g/a", "build"), bkStateBound, a1, false, StrengthExactArgv, ""},
		{"ambiguous, one shared key", ambiguousBinding(StrengthAmbiguous, a1, a1), bkStateBound, a1, false, StrengthAmbiguous, ""},
		{"weak tail, one shared key", ambiguousBinding(StrengthWeakTail, a1, a1), bkStateBound, a1, false, StrengthWeakTail, ""},
		{"session level, one shared key", ambiguousBinding(StrengthSessionLevel, a1), bkStateBound, a1, false, StrengthSessionLevel, ""},
		{"same project, different jobs -> project default", ambiguousBinding(StrengthAmbiguous, a1, a2), bkStateBound, PolicyKey{Project: "g/a"}, true, StrengthAmbiguous, ""},
		{"multi project -> audit", ambiguousBinding(StrengthAmbiguous, a1, b1), bkStateAmbiguous, PolicyKey{}, false, StrengthAmbiguous, EnfStateAmbiguous},
		{"environ tiebreak across projects never picks", CgroupBinding{
			SessionRef: "r-a", FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "build"},
			Strength: StrengthEnvironTiebreak, CandidateKeys: []PolicyKey{a1, b1},
		}, bkStateAmbiguous, PolicyKey{}, false, StrengthAmbiguous, EnfStateAmbiguous},
		{"environ tiebreak within one project binds", CgroupBinding{
			SessionRef: "r-a", FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "build"},
			Strength: StrengthEnvironTiebreak, CandidateKeys: []PolicyKey{a1, a1},
		}, bkStateBound, a1, false, StrengthEnvironTiebreak, ""},
		{"unroutable exact claim", exactBinding("", ""), bkStateUnattributed, PolicyKey{}, false, StrengthExactArgv, EnfStateUnattributed},
		{"unroutable among routable candidates", ambiguousBinding(StrengthSessionLevel, a1, PolicyKey{}), bkStateAmbiguous, PolicyKey{}, false, StrengthAmbiguous, EnfStateAmbiguous},
		{"no candidates", CgroupBinding{Ambiguous: true}, bkStateUnattributed, PolicyKey{}, false, StrengthAmbiguous, EnfStateUnattributed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := classify(tc.bind)
			if got.state != tc.state || got.key != tc.key || got.mixedJobs != tc.mixed || got.strength != tc.strength || got.reason != tc.enfReason {
				t.Fatalf("classify = %+v, want state=%d key=%v mixed=%v strength=%s reason=%q",
					got, tc.state, tc.key, tc.mixed, tc.strength, tc.enfReason)
			}
		})
	}
}

// ---- binding to datapath state ----

func TestBinder_ExactBindsEnforceSlot(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "build", enforcePol(1, "93.184.216.34"))

	r.b.OnBind(100, exactBinding("g/a", "build"))
	r.b.OnBind(101, exactBinding("g/a", "build"))

	p100, ok := r.dp.cg(100)
	if !ok || p100.State != bkStateBound || p100.Mode != bkModeBlock {
		t.Fatalf("cg 100 = %+v, ok=%v", p100, ok)
	}

	p101, _ := r.dp.cg(101)
	if p101.Slot != p100.Slot {
		t.Fatalf("parallel builds of one project must share a slot: %d vs %d", p100.Slot, p101.Slot)
	}

	if r.dp.installs != 1 {
		t.Fatalf("installs = %d, want 1", r.dp.installs)
	}

	rules := r.dp.slots[p100.Slot]
	if len(rules.Allow) != 1 || rules.Allow[0].IP != "93.184.216.34" || len(rules.Deny) != 0 {
		t.Fatalf("slot rules = %+v", rules)
	}
}

func TestBinder_ModeMapping(t *testing.T) {
	t.Parallel()

	for mode, want := range map[BuildPolicyMode]uint8{BuildModeAudit: bkModeAudit, BuildModeShadow: bkModeShadow, BuildModeEnforce: bkModeBlock} {
		r := newRig()
		p := enforcePol(1, "1.2.3.4")
		p.Mode = mode
		r.src.set("g/a", "j", p)
		r.b.OnBind(1, exactBinding("g/a", "j"))

		if got, _ := r.dp.cg(1); got.Mode != want || got.State != bkStateBound {
			t.Errorf("mode %s -> %+v, want mode %d", mode, got, want)
		}
	}
}

func TestBinder_MultiProjectStaysAudit(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "build", enforcePol(1, "1.2.3.4"))
	r.src.set("g/b", "build", enforcePol(1, "1.2.3.4"))

	r.b.OnBind(7, ambiguousBinding(StrengthAmbiguous, PolicyKey{"g/a", "build"}, PolicyKey{"g/b", "build"}))

	p, ok := r.dp.cg(7)
	if !ok || p.State != bkStateAmbiguous || p.Mode != bkModeAudit {
		t.Fatalf("multi-project cgroup = %+v ok=%v, want ambiguous/audit", p, ok)
	}

	if r.dp.installs != 0 {
		t.Fatal("no slot may be installed for an ambiguous cgroup")
	}
}

func TestBinder_MixedJobsBindsProjectDefault(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "", enforcePol(1, "9.9.9.9"))

	r.b.OnBind(7, ambiguousBinding(StrengthAmbiguous, PolicyKey{"g/a", "build"}, PolicyKey{"g/a", "test"}))

	if p, _ := r.dp.cg(7); p.State != bkStateBound {
		t.Fatalf("mixed jobs of one project should bind the project default, got %+v", p)
	}

	var key string

	r.b.mu.Lock()
	for _, d := range r.b.cgs {
		key = d.policyID
		if !d.mixedJobs {
			t.Error("decision not flagged mixedJobs")
		}
	}
	r.b.mu.Unlock()

	if key != "g/a@1/" {
		t.Fatalf("policy id = %q", key)
	}
}

func TestBinder_UnreliableHistoryAuditsNewCgroups(t *testing.T) {
	t.Parallel()

	down := true
	r := newRig(WithBinderHistory(func() bool { return down }, nil))
	r.src.set("g/a", "build", enforcePol(1, "1.2.3.4"))

	r.b.OnBind(1, exactBinding("g/a", "build"))

	if p, _ := r.dp.cg(1); p.State != bkStateDegraded || p.Mode != bkModeAudit {
		t.Fatalf("new cgroup while history down = %+v", p)
	}

	rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if rows[0].EnforcementState != EnfStateDegradedHist || rows[0].DegradedReason != EnfStateDegradedHist {
		t.Fatalf("row = %+v", rows[0])
	}

	// A cgroup bound while history was healthy keeps its slot.
	down = false

	r.b.OnBind(2, exactBinding("g/a", "build"))

	down = true

	r.b.OnBind(2, exactBinding("g/a", "build"))

	if p, _ := r.dp.cg(2); p.State != bkStateBound {
		t.Fatalf("existing bound cgroup must keep its slot, got %+v", p)
	}
}

func TestBinder_JoinOutcomeHistoryDown(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.b.OnJoinOutcome(5, "", JoinHistoryDown)

	if p, _ := r.dp.cg(5); p.State != bkStateDegraded {
		t.Fatalf("history_down outcome = %+v", p)
	}
}

func TestBinder_DeadlineSessionLevel(t *testing.T) {
	t.Parallel()

	mk := func(ref, project string) SessionState {
		return SessionState{
			Ref: ref, StartedAt: time.Unix(1_000_000, 0).Add(-time.Second),
			FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: project, FrontendAttrKeyJobName: "build"},
		}
	}

	sessions := func(open ...SessionState) SessionsLookup {
		return func(time.Time) ([]SessionState, bool) { return open, true }
	}

	t.Run("lone session binds", func(t *testing.T) {
		t.Parallel()

		r := newRig(WithBinderHistory(func() bool { return false }, sessions(mk("r1", "g/a"))))
		r.src.set("g/a", "build", enforcePol(1, "1.2.3.4"))
		r.b.OnJoinOutcome(9, "", JoinDeadline)

		if p, _ := r.dp.cg(9); p.State != bkStateBound {
			t.Fatalf("= %+v", p)
		}
	})

	t.Run("two projects stay audit", func(t *testing.T) {
		t.Parallel()

		r := newRig(WithBinderHistory(func() bool { return false }, sessions(mk("r1", "g/a"), mk("r2", "g/b"))))
		r.src.set("g/a", "build", enforcePol(1, "1.2.3.4"))
		r.b.OnJoinOutcome(9, "", JoinDeadline)

		if p, _ := r.dp.cg(9); p.State != bkStateAmbiguous || p.Mode != bkModeAudit {
			t.Fatalf("= %+v", p)
		}
	})

	t.Run("unreliable session set is degraded", func(t *testing.T) {
		t.Parallel()

		unreliable := func(time.Time) ([]SessionState, bool) { return nil, false }
		r := newRig(WithBinderHistory(func() bool { return false }, unreliable))
		r.b.OnJoinOutcome(9, "", JoinDeadline)

		if p, _ := r.dp.cg(9); p.State != bkStateDegraded {
			t.Fatalf("= %+v", p)
		}
	})

	t.Run("none open is unattributed", func(t *testing.T) {
		t.Parallel()

		r := newRig(WithBinderHistory(func() bool { return false }, sessions()))
		r.b.OnJoinOutcome(9, "", JoinDeadline)

		if p, _ := r.dp.cg(9); p.State != bkStateUnattributed {
			t.Fatalf("= %+v", p)
		}
	})
}

func TestBinder_CapacityExhaustionAudits(t *testing.T) {
	t.Parallel()

	t.Run("no free slot", func(t *testing.T) {
		t.Parallel()

		r := newRig(WithBinderMaxSlots(1))
		r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
		r.src.set("g/b", "j", enforcePol(1, "2.2.2.2"))

		r.b.OnBind(1, exactBinding("g/a", "j"))
		r.b.OnBind(2, exactBinding("g/b", "j"))

		if p, _ := r.dp.cg(1); p.State != bkStateBound {
			t.Fatalf("first = %+v", p)
		}

		p2, _ := r.dp.cg(2)
		if p2.State != bkStateDegraded || p2.Mode != bkModeAudit {
			t.Fatalf("second = %+v, want degraded audit", p2)
		}

		rows := []Violation{{CgroupID: 2, Action: "packet_observed", Timestamp: r.clk.now()}}
		r.b.Annotate(rows)

		if rows[0].EnforcementState != EnfStateDegradedCap || rows[0].DegradedReason != EnfStateDegradedCap {
			t.Fatalf("row = %+v", rows[0])
		}

		if r.b.Stats().CapacityEvents != 1 {
			t.Fatalf("capacity events = %d", r.b.Stats().CapacityEvents)
		}
	})

	t.Run("inner map install fails (E2BIG)", func(t *testing.T) {
		t.Parallel()

		r := newRig()
		r.dp.failSlots = true
		r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
		r.b.OnBind(1, exactBinding("g/a", "j"))

		if p, _ := r.dp.cg(1); p.State != bkStateDegraded || p.Mode != bkModeAudit {
			t.Fatalf("= %+v", p)
		}

		if r.b.Stats().Slots != 0 || r.b.Stats().FreeSlots != bkMaxSlots {
			t.Fatalf("a failed install must not consume a slot: %+v", r.b.Stats())
		}
	})

	t.Run("cgroup table full", func(t *testing.T) {
		t.Parallel()

		r := newRig()
		r.dp.failCgs = true
		r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
		r.b.OnBind(1, exactBinding("g/a", "j"))

		rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()}}
		r.b.Annotate(rows)

		if rows[0].EnforcementState != EnfStateDegradedCap {
			t.Fatalf("row = %+v", rows[0])
		}

		r.b.GC(r.clk.now().Add(time.Hour))

		if r.b.Stats().Slots != 0 {
			t.Fatal("slot taken for a cgroup that could not be written should be released and collected")
		}
	})
}

func TestBinder_PolicyUnavailableAudits(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.b.OnBind(1, exactBinding("g/unknown", "j"))

	if p, _ := r.dp.cg(1); p.State != bkStateDegraded || p.Mode != bkModeAudit {
		t.Fatalf("= %+v", p)
	}

	rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if rows[0].EnforcementState != EnfStatePolicyUnavl {
		t.Fatalf("row = %+v", rows[0])
	}

	nilSrc := NewBuildPolicyBinder(nil, newFakeDP(), quietLog())
	nilSrc.OnBind(1, exactBinding("g/a", "j")) // must not panic
}

// ---- refcount, GC, update flip ----

func TestBinder_SlotRefcountAndGC(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))

	r.b.OnBind(1, exactBinding("g/a", "j"))
	r.b.OnBind(2, exactBinding("g/a", "j"))

	slot, _ := r.dp.cg(1)

	r.b.OnUnbind(1)
	r.b.GC(r.clk.now().Add(time.Hour))

	if r.b.Stats().Slots != 1 {
		t.Fatal("slot freed while a cgroup still holds it")
	}

	r.b.OnUnbind(2)
	r.clk.advance(slotIdleGrace - time.Second)
	r.b.GC(r.clk.now())

	if r.b.Stats().Slots != 1 {
		t.Fatal("slot freed before the idle grace")
	}

	// A new cgroup inside the grace reuses the slot without reinstalling.
	r.b.OnBind(3, exactBinding("g/a", "j"))

	if p, _ := r.dp.cg(3); p.Slot != slot.Slot || r.dp.installs != 1 {
		t.Fatalf("slot not reused inside grace: %+v installs=%d", p, r.dp.installs)
	}

	r.b.OnUnbind(3)
	r.clk.advance(slotIdleGrace + time.Second)
	r.b.GC(r.clk.now())

	if r.b.Stats().Slots != 0 || len(r.dp.removed) != 1 || r.dp.removed[0] != slot.Slot {
		t.Fatalf("slot not collected after grace: %+v removed=%v", r.b.Stats(), r.dp.removed)
	}

	if _, ok := r.dp.cg(1); ok {
		t.Fatal("kernel entry for an unbound cgroup must be deleted")
	}
}

func TestBinder_PolicyUpdateFlipsCgroups(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))

	r.b.OnBind(1, exactBinding("g/a", "j"))
	r.b.OnBind(2, exactBinding("g/a", "j"))

	old, _ := r.dp.cg(1)

	r.src.set("g/a", "j", enforcePol(2, "2.2.2.2"))
	r.src.notify("g/a")

	n1, _ := r.dp.cg(1)
	n2, _ := r.dp.cg(2)

	if n1.Slot == old.Slot || n1.Slot != n2.Slot {
		t.Fatalf("cgroups not flipped to one new slot: old=%+v n1=%+v n2=%+v", old, n1, n2)
	}

	if n1.Gen != old.Gen+1 {
		t.Fatalf("gen not bumped: %d -> %d", old.Gen, n1.Gen)
	}

	if got := r.dp.slots[n1.Slot].Allow[0].IP; got != "2.2.2.2" {
		t.Fatalf("new slot rules = %s", got)
	}

	// The old slot is still installed (drain), then collected after the grace.
	if _, ok := r.dp.slots[old.Slot]; !ok {
		t.Fatal("old slot removed immediately; flips must drain first")
	}

	r.clk.advance(slotIdleGrace + time.Second)
	r.b.GC(r.clk.now())

	if _, ok := r.dp.slots[old.Slot]; ok {
		t.Fatal("old slot not collected after grace")
	}

	// Rows now report the new policy id.
	rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if rows[0].PolicyKey != "g/a@2/j" {
		t.Fatalf("policy key = %q", rows[0].PolicyKey)
	}
}

func TestBinder_ModeOnlyChangeFlipsMode(t *testing.T) {
	t.Parallel()

	r := newRig()
	p := enforcePol(1, "1.1.1.1")
	p.Mode = BuildModeShadow
	r.src.set("g/a", "j", p)
	r.b.OnBind(1, exactBinding("g/a", "j"))

	before, _ := r.dp.cg(1)

	p.Mode = BuildModeEnforce // same version
	r.src.set("g/a", "j", p)
	r.src.notify("")

	after, _ := r.dp.cg(1)
	if after.Slot != before.Slot || after.Mode != bkModeBlock || after.Gen != before.Gen+1 {
		t.Fatalf("before=%+v after=%+v", before, after)
	}
}

func TestBinder_RefreshFailureKeepsInstalledPolicy(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	before, _ := r.dp.cg(1)

	r.src.mu.Lock()
	delete(r.src.pols, PolicyKey{"g/a", "j"})
	r.src.mu.Unlock()
	r.src.notify("g/a")

	if after, _ := r.dp.cg(1); after != before {
		t.Fatalf("a failed refresh changed enforcement: %+v -> %+v", before, after)
	}
}

func TestBinder_PrefetchWarmsCache(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))

	r.b.OnSessionRegistered(map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "j"})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.src.mu.Lock()
		n := r.src.fetches
		r.src.mu.Unlock()

		if n == 1 {
			break
		}

		time.Sleep(5 * time.Millisecond)
	}

	r.b.OnBind(1, exactBinding("g/a", "j"))

	r.src.mu.Lock()
	defer r.src.mu.Unlock()

	if r.src.fetches != 1 {
		t.Fatalf("fetches = %d, want 1 (prefetch then cached bind)", r.src.fetches)
	}
}

// ---- pre-bind re-evaluation and row annotation ----

func TestAnnotate_PreBindWouldBlock(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		mode      BuildPolicyMode
		ip        string
		port      int
		wantBlock bool
	}{
		{"enforce, denied by default", BuildModeEnforce, "6.6.6.6", 443, true},
		{"enforce, allowed ip", BuildModeEnforce, "1.1.1.1", 443, false},
		{"enforce, allowed ip wrong port", BuildModeEnforce, "1.1.1.1", 80, true},
		{"shadow, denied", BuildModeShadow, "6.6.6.6", 443, true},
		{"audit project never would_block", BuildModeAudit, "6.6.6.6", 443, false},
		{"loopback allowed", BuildModeEnforce, "127.0.0.1", 80, false},
		{"metadata always denied", BuildModeEnforce, "169.254.169.254", 80, true},
		{"DoT always denied", BuildModeEnforce, "1.1.1.1", 853, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig()
			p := enforcePol(1, "1.1.1.1")
			p.Mode = tc.mode
			r.src.set("g/a", "j", p)
			r.b.OnBind(1, exactBinding("g/a", "j"))

			rows := []Violation{{
				CgroupID: 1, IP: tc.ip, Port: tc.port, Action: "packet_observed",
				EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now(),
			}}
			r.b.Annotate(rows)

			v := rows[0]
			if v.WouldBlock != tc.wantBlock {
				t.Fatalf("WouldBlock=%v, want %v", v.WouldBlock, tc.wantBlock)
			}

			if v.EnforcementState != EnfStatePendingBind {
				t.Fatalf("state = %q, a pre-bind row stays pending_bind", v.EnforcementState)
			}

			if v.BindingStrength != StrengthExactArgv || v.PolicyKey != "g/a@1/j" || v.BindingVerified {
				t.Fatalf("row = %+v", v)
			}
		})
	}
}

func TestAnnotate_PreBindDenyRuleAndPrecedence(t *testing.T) {
	t.Parallel()

	r := newRig()
	p := BuildPolicy{Mode: BuildModeEnforce, Version: 1, IPRules: []BuildIPRule{
		{IP: "5.5.5.5", Port: 0, Allow: false, Prio: policy.RulePriority(0)},
		{IP: "5.5.5.5", Port: 443, Allow: true, Prio: policy.RulePriority(1)},
	}}
	r.src.set("g/a", "j", p)
	r.b.OnBind(1, exactBinding("g/a", "j"))

	rows := []Violation{{CgroupID: 1, IP: "5.5.5.5", Port: 443, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if !rows[0].WouldBlock {
		t.Fatal("earlier deny rule must beat the later allow")
	}
}

func TestAnnotate_PreBindTrustedNets(t *testing.T) {
	t.Parallel()

	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	r := newRig(WithBinderTrustedCIDRs([]net.IPNet{*n}))
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	rows := []Violation{{CgroupID: 1, IP: "10.1.2.3", Port: 80, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if rows[0].WouldBlock {
		t.Fatal("trusted network must not be would_block")
	}
}

func TestAnnotate_StateFromVerdict(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	rows := []Violation{
		{CgroupID: 1, Action: "packet_dropped", Timestamp: r.clk.now()},
		{CgroupID: 1, Action: "sinkhole_hit", Timestamp: r.clk.now()},
		{CgroupID: 1, Action: "would_block", Timestamp: r.clk.now()},
		{CgroupID: 1, Action: "packet_allowed", Timestamp: r.clk.now()},
		{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()},
		{CgroupID: 1, Action: "dns_bypass_dropped", Timestamp: r.clk.now()},
	}
	r.b.Annotate(rows)

	// Every verdict of an enforce slot carries "enforced", not audit_project.
	want := []string{EnfStateEnforced, EnfStateEnforced, EnfStateShadow, EnfStateEnforced, EnfStateEnforced, EnfStateEnforced}
	for i, w := range want {
		if rows[i].EnforcementState != w {
			t.Errorf("row %d (%s) state = %q, want %q", i, rows[i].Action, rows[i].EnforcementState, w)
		}
	}
}

func TestAnnotate_RetiredDecisionResolvesLateRows(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	ts := r.clk.now()

	r.clk.advance(time.Second)
	r.b.OnUnbind(1)

	rows := []Violation{{CgroupID: 1, IP: "6.6.6.6", Port: 80, EnforcementState: EnfStatePendingBind, Timestamp: ts}}
	r.b.Annotate(rows)

	if !rows[0].WouldBlock {
		t.Fatal("a row from a cgroup that has since been removed must still resolve")
	}

	// A row long after retirement belongs to a recycled id: untouched.
	late := []Violation{{CgroupID: 1, IP: "6.6.6.6", Port: 80, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now().Add(time.Minute)}}
	r.b.Annotate(late)

	if late[0].WouldBlock || late[0].PolicyKey != "" {
		t.Fatal("row after id-reuse grace must not take the retired decision")
	}
}

func TestFinalizeUnbound(t *testing.T) {
	t.Parallel()

	rows := []Violation{
		{EnforcementState: EnfStatePendingBind, BuildUnattributed: true},
		{EnforcementState: EnfStatePendingBind, BuildAmbiguous: true},
		{EnforcementState: EnfStatePendingBind},
		{EnforcementState: EnfStateShadow, BuildUnattributed: true},
	}
	FinalizeUnbound(rows)

	want := []string{EnfStateUnattributed, EnfStateAmbiguous, EnfStatePendingBind, EnfStateShadow}
	for i, w := range want {
		if rows[i].EnforcementState != w {
			t.Errorf("row %d = %q, want %q", i, rows[i].EnforcementState, w)
		}
	}
}

// ---- datapath event decode / verdict mapping ----

func TestActionForVerdict(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		verdict, reason uint8
		want            string
	}{
		{bkVerdictObserved, dropReasonPolicy, "packet_observed"},
		{bkVerdictWouldBlock, dropReasonPolicy, "would_block"},
		{bkVerdictWouldBlock, dropReasonSinkhole, "would_block"},
		{bkVerdictDropped, dropReasonPolicy, "packet_dropped"},
		{bkVerdictDropped, dropReasonSinkhole, "sinkhole_hit"},
		{bkVerdictAllowed, 0, "packet_allowed"},
		{bkVerdictHeld, dropReasonPolicy, "syn_held"},
		{0, dropReasonPolicy, "packet_observed"},
	} {
		if got := ActionForVerdict(tc.verdict, tc.reason); got != tc.want {
			t.Errorf("ActionForVerdict(%d,%d) = %q, want %q", tc.verdict, tc.reason, got, tc.want)
		}
	}
}

func TestDecodeBKEvent(t *testing.T) {
	t.Parallel()

	raw := make([]byte, minBKDropEventSize)
	copy(raw[0:4], []byte{93, 184, 216, 34})
	raw[4], raw[5] = 0xBB, 0x01 // 443 LE
	raw[6] = 6
	raw[7] = 42 // cgroup id low byte
	raw[15] = dropReasonPolicy
	raw[16] = 7 // pid
	copy(raw[20:], "curl")
	copy(raw[36:], "/usr/bin/curl")
	raw[292] = bkVerdictWouldBlock
	raw[293] = bkStatePending

	v, state, ok := decodeBKEvent(raw, time.Unix(5, 0))
	if !ok {
		t.Fatal("decode failed")
	}

	if v.IP != "93.184.216.34" || v.Port != 443 || v.CgroupID != 42 || v.PID != 7 || v.Comm != "curl" ||
		v.BinaryPath != "/usr/bin/curl" || v.Action != "would_block" || state != bkStatePending ||
		v.EnforcementState != EnfStatePendingBind {
		t.Fatalf("decoded = %+v state=%d", v, state)
	}

	raw[293] = bkStateBound

	v, _, _ = decodeBKEvent(raw, time.Now())
	if v.EnforcementState != "" {
		t.Fatalf("bound-state event must not be pending_bind, got %q", v.EnforcementState)
	}

	if _, _, ok = decodeBKEvent(raw[:100], time.Now()); ok {
		t.Fatal("short record decoded")
	}

	raw[16] = 0

	if _, _, ok = decodeBKEvent(raw, time.Now()); ok {
		t.Fatal("pid 0 (kernel context) decoded")
	}
}

// ---- policy rendering / sources ----

func TestRenderBuildPolicy(t *testing.T) {
	t.Parallel()

	pol := &policy.ResolvedPolicy{
		ProjectPath: "g/a",
		Action:      policy.ActionBlock,
		JobActions:  map[string]string{"lint": policy.ActionAudit},
		Enrolled:    true,
		Version:     3,
		RuleSets: map[string][]policy.Rule{"": {
			{Pattern: "10.0.0.5", PatternType: policy.PatternCIDR, Action: policy.ActionDeny},
			{Pattern: "93.184.216.34", PatternType: policy.PatternCIDR, Action: policy.ActionAllow, Ports: []int{443}},
			{Pattern: "example.org", PatternType: policy.PatternFQDN, Action: policy.ActionAllow, Ports: []int{443}},
		}},
	}

	bp := RenderBuildPolicy(pol, "build", BuildModeEnforce, nil)
	if bp.Mode != BuildModeEnforce || bp.Version != 3 {
		t.Fatalf("bp = %+v", bp)
	}

	if len(bp.IPRules) != 2 || bp.IPRules[0].Allow || bp.IPRules[0].Prio != policy.RulePriority(0) ||
		!bp.IPRules[1].Allow || bp.IPRules[1].Port != 443 || bp.IPRules[1].Prio != policy.RulePriority(1) {
		t.Fatalf("ip rules = %+v", bp.IPRules)
	}

	if len(bp.FQDNRules) != 1 || bp.FQDNRules[0].Pattern != "example.org" || !bp.FQDNRules[0].Allow || bp.FQDNRules[0].Prio != policy.RulePriority(2) {
		t.Fatalf("fqdn rules = %+v", bp.FQDNRules)
	}

	if got := RenderBuildPolicy(pol, "lint", BuildModeEnforce, nil); got.Mode != BuildModeAudit {
		t.Fatalf("audit job action must render audit, got %s", got.Mode)
	}

	if got := RenderBuildPolicy(pol, "build", BuildModeAudit, nil); got.Mode != BuildModeAudit {
		t.Fatalf("audit rollout must render audit, got %s", got.Mode)
	}

	if got := RenderBuildPolicy(pol, "build", BuildModeShadow, nil); got.Mode != BuildModeShadow {
		t.Fatalf("shadow rollout, got %s", got.Mode)
	}

	pol.Enrolled = false
	if got := RenderBuildPolicy(pol, "build", BuildModeEnforce, nil); got.Mode != BuildModeAudit {
		t.Fatalf("not enrolled must render audit, got %s", got.Mode)
	}
}

type stubProvider struct {
	pol *policy.ResolvedPolicy
	err error
}

func (s stubProvider) GetPolicy(context.Context, string) (*policy.ResolvedPolicy, error) {
	return s.pol, s.err
}

func TestProviderBuildPolicySource(t *testing.T) {
	t.Parallel()

	mode := BuildModeShadow
	pol := &policy.ResolvedPolicy{ProjectPath: "g/a", Action: policy.ActionBlock, Enrolled: true, Version: 2}
	src := NewProviderBuildPolicySource(stubProvider{pol: pol}, func(string) BuildPolicyMode { return mode }, nil)

	a, err := src.Policy(t.Context(), "g/a", "j")
	if err != nil || a.Mode != BuildModeShadow {
		t.Fatalf("a=%+v err=%v", a, err)
	}

	mode = BuildModeEnforce

	b, _ := src.Policy(t.Context(), "g/a", "j")
	if b.Version == a.Version {
		t.Fatal("a rollout-mode change must change the slot version")
	}

	missing := NewProviderBuildPolicySource(stubProvider{err: policy.ErrNoPolicy}, nil, nil)
	if _, err = missing.Policy(t.Context(), "g/x", ""); !errors.Is(err, ErrBuildPolicyUnavailable) {
		t.Fatalf("err = %v, want unavailable", err)
	}

	got := make(chan string, 1)
	cancel := src.Watch(func(p string) { got <- p })
	src.Notify("g/a")

	if p := <-got; p != "g/a" {
		t.Fatalf("notified %q", p)
	}

	cancel()
	src.Notify("g/a")

	select {
	case <-got:
		t.Fatal("notified after cancel")
	default:
	}
}

func TestParseBuildPolicyMode(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]BuildPolicyMode{"": BuildModeAudit, "audit": BuildModeAudit, "shadow": BuildModeShadow, "enforce": BuildModeEnforce} {
		if got, err := ParseBuildPolicyMode(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}

	if _, err := ParseBuildPolicyMode("block"); !errors.Is(err, ErrBuildPolicyMode) {
		t.Fatalf("err = %v", err)
	}
}

func mkdirAndWrite(dir, name, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
}

func TestAnnotate_StateFollowsSlotMode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		mode BuildPolicyMode
		want map[string]string
	}{
		{BuildModeShadow, map[string]string{
			"packet_allowed": EnfStateShadow, "packet_observed": EnfStateShadow,
			"would_block": EnfStateShadow, "dns_bypass_dropped": EnfStateEnforced,
		}},
		{BuildModeAudit, map[string]string{
			"packet_allowed": EnfStateAuditProject, "packet_observed": EnfStateAuditProject,
		}},
	} {
		r := newRig()
		pol := enforcePol(1, "1.1.1.1")
		pol.Mode = tc.mode
		r.src.set("g/a", "j", pol)
		r.b.OnBind(1, exactBinding("g/a", "j"))

		for action, want := range tc.want {
			rows := []Violation{{CgroupID: 1, Action: action, Timestamp: r.clk.now()}}
			r.b.Annotate(rows)

			if rows[0].EnforcementState != want {
				t.Errorf("mode %s action %s: state %q, want %q", tc.mode, action, rows[0].EnforcementState, want)
			}
		}
	}
}

func TestRefreshHold_FollowsEnforcePolicies(t *testing.T) {
	t.Parallel()

	r := newRig()

	r.b.RefreshHold()

	if r.dp.hold {
		t.Fatal("hold on with no policies")
	}

	// A shadow-only binding never turns the hold on.
	shadow := enforcePol(1, "1.1.1.1")
	shadow.Mode = BuildModeShadow
	r.src.set("g/s", "j", shadow)
	r.b.OnBind(1, exactBinding("g/s", "j"))
	r.b.RefreshHold()

	if r.dp.hold {
		t.Fatal("hold on for a shadow-only cluster")
	}

	// A bound enforce cgroup does.
	r.src.set("g/e", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(2, exactBinding("g/e", "j"))
	r.b.RefreshHold()

	if !r.dp.hold {
		t.Fatal("hold off with a bound enforce cgroup")
	}

	calls := r.dp.holdCalls
	r.b.RefreshHold()

	if r.dp.holdCalls != calls {
		t.Fatal("RefreshHold must not rewrite an unchanged flag")
	}

	r.b.OnUnbind(2)
	r.b.RefreshHold()

	if r.dp.hold {
		t.Fatal("hold still on after the last enforce cgroup went away")
	}
}

func TestRefreshHold_PrefetchedEnforceSession(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/e", "j", enforcePol(1, "1.1.1.1"))

	// A session registration prefetches the policy; the hold must be on
	// before any cgroup of the session exists, and expire afterwards.
	r.b.OnSessionRegistered(map[string]string{FrontendAttrKeyProjectPath: "g/e", FrontendAttrKeyJobName: "j"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.dp.mu.Lock()
		on := r.dp.hold
		r.dp.mu.Unlock()

		if on {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if !r.dp.hold {
		t.Fatal("hold not enabled by an enforce session prefetch")
	}

	r.clk.advance(holdSeenTTL + time.Second)
	r.b.RefreshHold()

	if r.dp.hold {
		t.Fatal("hold must lapse once the prefetch is stale and no session is open")
	}
}

func TestAnnotate_HeldSynReevaluatedAfterBind(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	rows := []Violation{
		{CgroupID: 1, IP: "9.9.9.9", Port: 443, Action: ActionSynHeld, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now()},
		{CgroupID: 1, IP: "1.1.1.1", Port: 443, Action: ActionSynHeld, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now()},
	}
	r.b.Annotate(rows)

	if !rows[0].WouldBlock {
		t.Error("held SYN to a destination the slot denies must be would_block")
	}

	if rows[1].WouldBlock {
		t.Error("held SYN to a destination the slot allows must not be would_block")
	}

	if rows[0].EnforcementState != EnfStatePendingBind {
		t.Errorf("held row state = %q, want pending_bind", rows[0].EnforcementState)
	}
}
