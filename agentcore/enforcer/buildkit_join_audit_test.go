package enforcer

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

// recObserver records binding observer calls.
type recObserver struct {
	mu       sync.Mutex
	binds    map[uint64]CgroupBinding
	unbinds  []uint64
	outcomes map[uint64]JoinOutcome
	sessions int
}

func newRecObserver() *recObserver {
	return &recObserver{binds: map[uint64]CgroupBinding{}, outcomes: map[uint64]JoinOutcome{}}
}

func (o *recObserver) OnBind(id uint64, b CgroupBinding) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.binds[id] = b
}

func (o *recObserver) OnUnbind(id uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.unbinds = append(o.unbinds, id)
}

func (o *recObserver) OnJoinOutcome(id uint64, _ string, out JoinOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.outcomes[id] = out
}

func (o *recObserver) OnSessionRegistered(map[string]string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.sessions++
}

func (o *recObserver) outcome(id uint64) (JoinOutcome, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	v, ok := o.outcomes[id]

	return v, ok
}

// Decision 2: the fail-closed kill switch is an explicit opt-in. By
// default an unattributable or untrusted join is flagged and audited.

func TestJoinerDefault_UnauthorizedSessionFlaggedNotKilled(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
	reg.RegisterSession("rBad", time.Unix(1, 0), nil)
	reg.UpsertVertex("rBad", VertexState{Digest: "dBad", Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})

	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-un", 61, "/bin/sh\x00-c\x00make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-un", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4321)

		return ok && b.SessionRef == "rBad" && b.Flag == BuildFlagMissingCI
	})

	if h.killed() {
		t.Fatal("default config killed an unauthorized-session cgroup")
	}

	b, _ := reg.LookupByCgroupID(4321)
	if b.Strength != StrengthExactArgv || len(b.CandidateKeys) != 1 {
		t.Fatalf("binding = %+v", b)
	}

	// The claim is empty, so the binder would audit it: unattributed.
	if got := classify(b); got.state != bkStateUnattributed {
		t.Fatalf("classify = %+v, want unattributed", got)
	}

	var v Violation
	applyBuildKitBinding(&v, b)

	if v.BuildFlag != BuildFlagMissingCI || v.BindingStrength != StrengthExactArgv {
		t.Fatalf("row = %+v", v)
	}
}

// A definite deny-pattern match on a single exactly-linked vertex is
// explicit operator policy: it kills with or without the opt-in.
func TestJoiner_DefiniteDenyPatternAlwaysKills(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		reg := NewSessionRegistry(time.Minute)
		reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{regexp.MustCompile(`curl https?://`)})
		reg.RegisterSession("rA", time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/a"})
		reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: "[s 1/1] RUN curl http://x.example", StartedAt: time.Unix(2, 0)})

		h := newJoinHarness(t, reg, 0, WithKillOnUnattributed(optIn))
		cg := h.stage(t, "ctr-deny", 62, "/bin/sh\x00-c\x00curl http://x.example\x00")
		h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-deny", CgroupPath: cg}

		waitFor(t, time.Second, h.killed)

		if _, ok := reg.LookupByCgroupID(4321); ok {
			t.Fatalf("optIn=%v: a killed cgroup was linked", optIn)
		}
	}
}

// An ambiguous candidate set matching a deny pattern is only flagged by
// default; the opt-in kills it.
func TestJoiner_AmbiguousDenyPatternFlagOrKill(t *testing.T) {
	setup := func() *SessionRegistry {
		reg := NewSessionRegistry(time.Minute)
		reg.SetBuildVertexDenyPatterns([]*regexp.Regexp{regexp.MustCompile(`curl https?://`)})

		for _, ref := range []string{"rA", "rB"} {
			reg.RegisterSession(ref, time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/a"})
			reg.UpsertVertex(ref, VertexState{Digest: "d" + ref, Name: "[s 1/1] RUN curl http://x.example", StartedAt: time.Unix(2, 0)})
		}

		return reg
	}

	reg := setup()
	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-amb", 70, "/bin/sh\x00-c\x00curl http://x.example\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-amb", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4321)

		return ok && b.Ambiguous && b.Flag == BuildFlagDenyPattern
	})

	if h.killed() {
		t.Fatal("default config killed an ambiguous deny-pattern cgroup")
	}

	reg2 := setup()
	h2 := newJoinHarness(t, reg2, 0, WithKillOnUnattributed(true))
	cg2 := h2.stage(t, "ctr-amb", 71, "/bin/sh\x00-c\x00curl http://x.example\x00")
	h2.source.creates <- CgroupCreateEvent{ContainerID: "ctr-amb", CgroupPath: cg2}

	waitFor(t, time.Second, h2.killed)
}

func TestJoinerDefault_SpoofedArgvFlaggedNotKilled(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
	authedSession(reg, "rA", "[s 1/1] RUN make")
	reg.RegisterSession("rB", time.Unix(1, 0), nil) // unauthorized

	h := newJoinHarness(t, reg, 60*time.Millisecond)
	cg := h.stage(t, "ctr-spoof", 63, "make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-spoof", CgroupPath: cg}

	waitFor(t, 2*time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4321)

		return ok && b.Flag == BuildFlagArgvUntrusted
	})

	if h.killed() {
		t.Fatal("default config killed a spoof-suspect cgroup")
	}
}

func TestJoinerDefault_UnmatchedUnderRiskyPolicyBoundAmbiguousWithFlag(t *testing.T) {
	const frontend = "/bin/sh\x00-c\x00/run/frontend-entrypoint\x00"

	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
	authedSession(reg, "rA", "[s 1/1] RUN make")
	reg.RegisterSession("rBad", time.Unix(1, 0), nil)

	h := newJoinHarness(t, reg, 60*time.Millisecond)
	cg := h.stage(t, "ctr-fe", 64, frontend)
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

	waitFor(t, 2*time.Second, func() bool {
		b, ok := reg.LookupByCgroupID(4321)

		return ok && b.Ambiguous && b.Flag == BuildFlagUnmatched && b.Strength == StrengthSessionLevel
	})

	if h.killed() {
		t.Fatal("default config killed an unmatched cgroup")
	}
}

func TestJoinerDefault_HistoryDownIsAuditOutcomeNotKill(t *testing.T) {
	const frontend = "/bin/sh\x00-c\x00/run/frontend-entrypoint\x00"

	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
	reg.SetHistoryConnected(false)

	obs := newRecObserver()
	reg.SetBindingObserver(obs)

	h := newJoinHarness(t, reg, 60*time.Millisecond)
	cg := h.stage(t, "ctr-fe", 65, frontend)
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-fe", CgroupPath: cg}

	waitFor(t, 2*time.Second, func() bool {
		o, ok := obs.outcome(4321)

		return ok && o == JoinHistoryDown
	})

	if h.killed() {
		t.Fatal("history-down cgroup killed under default config")
	}
}

func TestJoiner_KillOptInStillKills(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.SetCIRequirement(true, []string{FrontendAttrKeyProjectPath})
	reg.RegisterSession("rBad", time.Unix(1, 0), nil)
	reg.UpsertVertex("rBad", VertexState{Digest: "dBad", Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})

	h := newJoinHarness(t, reg, 0, WithKillOnUnattributed(true))
	cg := h.stage(t, "ctr-un", 66, "/bin/sh\x00-c\x00make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-un", CgroupPath: cg}

	waitFor(t, time.Second, h.killed)
}

func TestJoiner_DeadlineOutcomeReported(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	obs := newRecObserver()
	reg.SetBindingObserver(obs)

	h := newJoinHarness(t, reg, 60*time.Millisecond)
	cg := h.stage(t, "ctr-orphan", 67, "/bin/sh\x00-c\x00nothing-pending\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-orphan", CgroupPath: cg}

	waitFor(t, 2*time.Second, func() bool {
		o, ok := obs.outcome(4321)

		return ok && o == JoinDeadline
	})
}

func TestJoiner_BindingCarriesStrengthAndCandidateKeys(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	reg.RegisterSession("rA", time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "build"})
	reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})

	obs := newRecObserver()
	reg.SetBindingObserver(obs)

	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-x", 68, "/bin/sh\x00-c\x00make\x00")
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-x", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		obs.mu.Lock()
		defer obs.mu.Unlock()

		return len(obs.binds) == 1
	})

	obs.mu.Lock()
	b := obs.binds[4321]
	obs.mu.Unlock()

	if b.Strength != StrengthExactArgv || len(b.CandidateKeys) != 1 || b.CandidateKeys[0] != (PolicyKey{"g/a", "build"}) {
		t.Fatalf("binding = %+v", b)
	}
}

// The environ tiebreak still picks the row attribution but the binder
// must see every candidate, and across projects it must not enforce.
func TestJoiner_EnvironTiebreakAcrossProjectsIsAmbiguousForBinder(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)

	for _, p := range []string{"g/a", "g/b"} {
		ref := "r-" + p
		reg.RegisterSession(ref, time.Unix(1, 0), map[string]string{
			FrontendAttrKeyProjectPath: p, FrontendAttrKeyJobName: "build",
		})
		reg.UpsertVertex(ref, VertexState{Digest: "d-" + ref, Name: "[s 1/1] RUN make", StartedAt: time.Unix(2, 0)})
	}

	obs := newRecObserver()
	reg.SetBindingObserver(obs)

	h := newJoinHarness(t, reg, 0)
	cg := h.stage(t, "ctr-tb", 69, "/bin/sh\x00-c\x00make\x00")

	// The RUN's own environ claims project a (forgeable).
	environ := "LEITWACHT_CI_PROJECT_PATH=g/a\x00LEITWACHT_CI_JOB_NAME=build\x00"
	if err := os.WriteFile(filepath.Join(h.root, "proc", strconv.Itoa(69), "environ"), []byte(environ), 0o600); err != nil {
		t.Fatal(err)
	}

	_ = cg
	h.source.creates <- CgroupCreateEvent{ContainerID: "ctr-tb", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		obs.mu.Lock()
		defer obs.mu.Unlock()

		return len(obs.binds) == 1
	})

	obs.mu.Lock()
	b := obs.binds[4321]
	obs.mu.Unlock()

	if b.Strength != StrengthEnvironTiebreak || len(uniqueKeys(b.CandidateKeys)) != 2 {
		t.Fatalf("binding = %+v", b)
	}

	if got := classify(b); got.state != bkStateAmbiguous {
		t.Fatalf("environ tiebreak across projects must not bind: %+v", got)
	}
}

func TestRegistry_ObserverSeesBindUnbindAndSessions(t *testing.T) {
	reg := NewSessionRegistry(time.Minute)
	obs := newRecObserver()
	reg.SetBindingObserver(obs)

	reg.RegisterSession("r1", time.Unix(1, 0), map[string]string{FrontendAttrKeyProjectPath: "g/a"})
	reg.LinkCgroup(5, CgroupBinding{SessionRef: "r1", ContainerID: "c5"})
	reg.UnlinkCgroup(5)
	reg.UnlinkCgroup(5) // not tracked: no second notification

	obs.mu.Lock()
	defer obs.mu.Unlock()

	if obs.sessions != 1 || len(obs.binds) != 1 || len(obs.unbinds) != 1 {
		t.Fatalf("sessions=%d binds=%d unbinds=%v", obs.sessions, len(obs.binds), obs.unbinds)
	}

	// Compare-and-clear: an old owner must not remove its replacement.
	other := newRecObserver()
	reg.SetBindingObserver(other)
	reg.ClearBindingObserver(obs)

	if reg.obs() == nil {
		t.Fatal("stale ClearBindingObserver removed the replacement")
	}
}
