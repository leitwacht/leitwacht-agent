package enforcer

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// Deny-class verdicts must never be lost to the cap behind a flood of
// packet_allowed rows.
func TestRecorder_AllowedRowsHaveOwnCap(t *testing.T) {
	t.Parallel()

	r := NewViolationRecorder(nil)
	r.SetBucketMode()

	for range 3 * maxViolationsPerBucket {
		r.RecordViolation(Violation{Action: "packet_allowed", IP: "1.1.1.1"})
	}

	deny := []string{"packet_dropped", "would_block", "sinkhole_hit", "dns_bypass_dropped", "packet_observed"}
	for _, a := range deny {
		r.RecordViolation(Violation{Action: a, IP: "6.6.6.6"})
	}

	vs, _, overflow := r.SnapshotAndReset()

	got := map[string]int{}
	for _, v := range vs {
		got[v.Action]++
	}

	for _, a := range deny {
		if got[a] != 1 {
			t.Errorf("%s rows = %d, want 1 (lost behind allowed rows)", a, got[a])
		}
	}

	if got["packet_allowed"] != maxViolationsPerBucket {
		t.Errorf("allowed rows = %d, want cap %d", got["packet_allowed"], maxViolationsPerBucket)
	}

	if overflow != int64(2*maxViolationsPerBucket) {
		t.Errorf("overflow = %d, want %d (allowed rows over the cap are counted)", overflow, 2*maxViolationsPerBucket)
	}

	// The deny cap itself is unchanged and independent of allowed rows.
	for range 2 * maxViolationsPerBucket {
		r.RecordViolation(Violation{Action: "packet_allowed"})
	}

	for range maxViolationsPerBucket + 5 {
		r.RecordViolation(Violation{Action: "packet_dropped"})
	}

	vs, _, overflow = r.SnapshotAndReset()

	drops := 0

	for _, v := range vs {
		if v.Action == "packet_dropped" {
			drops++
		}
	}

	if drops != maxViolationsPerBucket || overflow != int64(maxViolationsPerBucket+5) {
		t.Errorf("drops=%d overflow=%d", drops, overflow)
	}
}

func TestClassify_ArgvUntrustedIsAmbiguous(t *testing.T) {
	t.Parallel()

	b := exactBinding("g/a", "build")
	b.Flag = BuildFlagArgvUntrusted

	if got := classify(b); got.state != bkStateAmbiguous {
		t.Fatalf("argv_untrusted exact link bound: %+v", got)
	}

	w := ambiguousBinding(StrengthWeakTail, PolicyKey{"g/a", "build"})
	if got := classify(w); got.state != bkStateBound || got.strength != StrengthWeakTail {
		t.Fatalf("weak tail within one project must keep binding as weak_tail: %+v", got)
	}
}

func TestBinder_FailedWriteKeepsAccounting(t *testing.T) {
	t.Parallel()

	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	r.dp.failCgs = true
	r.b.OnBind(1, exactBinding("g/a", "j")) // rebind, kernel write fails

	if _, ok := r.dp.cg(1); ok {
		t.Fatal("a failed write must delete the kernel entry (fall back to pending/audit)")
	}

	rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if rows[0].EnforcementState != EnfStateDegradedCap {
		t.Fatalf("row = %+v", rows[0])
	}

	// No slot reference leaked: unbinding frees it after the grace.
	r.dp.failCgs = false
	r.b.OnUnbind(1)
	r.clk.advance(slotIdleGrace + time.Second)
	r.b.GC(r.clk.now())

	if r.b.Stats().Slots != 0 || r.b.Stats().FreeSlots != bkMaxSlots {
		t.Fatalf("leaked slot reference: %+v", r.b.Stats())
	}

	// Bound -> audit transition whose audit write fails: old slot released too.
	r.b.OnBind(2, exactBinding("g/a", "j"))

	r.dp.failCgs = true
	r.b.OnBind(2, ambiguousBinding(StrengthAmbiguous, PolicyKey{"g/a", "j"}, PolicyKey{"g/b", "j"}))

	if _, ok := r.dp.cg(2); ok {
		t.Fatal("stale bound entry left in the kernel after a failed audit write")
	}

	r.dp.failCgs = false
	r.b.OnUnbind(2)
	r.clk.advance(slotIdleGrace + time.Second)
	r.b.GC(r.clk.now())

	if r.b.Stats().Slots != 0 {
		t.Fatalf("leaked slot reference after failed audit write: %+v", r.b.Stats())
	}
}

// gatedSource blocks the first Policy call until released, returning the
// policy as it was when the call started (a slow remote source).
type gatedSource struct {
	*fakeSource
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newGatedSource() *gatedSource {
	return &gatedSource{fakeSource: newFakeSource(), entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gatedSource) Policy(ctx context.Context, project, job string) (BuildPolicy, error) {
	pol, err := g.fakeSource.Policy(ctx, project, job)

	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})

	return pol, err
}

func TestBinder_UnbindDuringFetchDoesNotLeak(t *testing.T) {
	t.Parallel()

	src := newGatedSource()
	src.set("g/a", "j", enforcePol(1, "1.1.1.1"))

	reg := NewSessionRegistry(time.Minute)
	dp := newFakeDP()
	b := NewBuildPolicyBinder(src, dp, quietLog(), WithBinderCgroupCheck(reg.bindingFor, nil))
	reg.SetBindingObserver(b)

	done := make(chan struct{})

	go func() {
		defer close(done)

		reg.LinkCgroup(9, CgroupBinding{
			SessionRef: "r", ContainerID: "c9",
			FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "j"},
			Strength:      StrengthExactArgv, CandidateKeys: []PolicyKey{{"g/a", "j"}},
		})
	}()

	<-src.entered

	// The cgroup is removed while OnBind waits for the policy.
	reg.UnlinkCgroup(9)
	close(src.release)
	<-done

	if _, ok := dp.cg(9); ok {
		t.Fatal("late bind installed a kernel entry for a removed cgroup")
	}

	st := b.Stats()
	if st.BoundCgroups != 0 || st.Slots != 0 {
		t.Fatalf("leaked state after unbind-during-fetch: %+v", st)
	}

	b.mu.Lock()
	n := len(b.cgs)
	b.mu.Unlock()

	if n != 0 {
		t.Fatalf("decision leaked: %d", n)
	}
}

func TestBinder_SweepReleasesGoneCgroups(t *testing.T) {
	t.Parallel()

	gone := false
	stat := func(string) (uint64, error) {
		if gone {
			return 0, os.ErrNotExist
		}

		return 5, nil
	}

	r := newRig(WithBinderCgroupCheck(nil, stat))
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))

	bd := exactBinding("g/a", "j")
	bd.CgroupPath = "/x/c5"
	r.b.OnBind(5, bd)

	r.b.Sweep()

	if _, ok := r.dp.cg(5); !ok {
		t.Fatal("live cgroup swept")
	}

	gone = true

	r.b.Sweep()

	if _, ok := r.dp.cg(5); ok {
		t.Fatal("entry for a vanished cgroup left in the kernel")
	}

	if r.b.Stats().BoundCgroups != 0 {
		t.Fatal("decision left after sweep")
	}

	// A bind for a cgroup that is already gone is not installed.
	r.b.OnBind(6, bd)

	if _, ok := r.dp.cg(6); ok {
		t.Fatal("bind for an already-removed cgroup installed")
	}
}

func TestBinder_PolicyChangeDuringFetchRefetches(t *testing.T) {
	t.Parallel()

	src := newGatedSource()
	src.set("g/a", "j", enforcePol(1, "1.1.1.1"))

	dp := newFakeDP()
	b := NewBuildPolicyBinder(src, dp, quietLog())

	done := make(chan struct{})

	go func() {
		defer close(done)

		b.OnBind(1, exactBinding("g/a", "j"))
	}()

	<-src.entered

	// v2 published and announced while OnBind holds the v1 policy.
	src.set("g/a", "j", enforcePol(2, "2.2.2.2"))
	src.notify("g/a")
	close(src.release)
	<-done

	p, ok := dp.cg(1)
	if !ok {
		t.Fatal("not bound")
	}

	if got := dp.slots[p.Slot].Allow[0].IP; got != "2.2.2.2" {
		t.Fatalf("bound to a stale policy version: %s", got)
	}
}

func TestBinder_FQDNRulesInactiveFlagged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	log := slog.New(slog.NewTextHandler(&buf, nil))
	dp := newFakeDP()
	src := newFakeSource()
	b := NewBuildPolicyBinder(src, dp, log)

	withFQDN := enforcePol(1, "1.1.1.1")
	withFQDN.FQDNRules = []BuildFQDNRule{{Pattern: "example.org", Allow: true, Prio: 2}}
	src.set("g/a", "j", withFQDN)

	audit := withFQDN
	audit.Mode = BuildModeAudit
	src.set("g/b", "j", audit)

	b.OnBind(1, exactBinding("g/a", "j"))
	b.OnBind(2, exactBinding("g/a", "j"))
	b.OnBind(3, exactBinding("g/b", "j"))

	if n := strings.Count(buf.String(), "domain rules not yet enforced"); n != 1 {
		t.Fatalf("error logged %d times, want once per policy version", n)
	}

	if !strings.Contains(buf.String(), "level=ERROR") {
		t.Fatal("enforce + fqdn rules must log at Error")
	}

	rows := []Violation{
		{CgroupID: 1, Action: "packet_observed", Timestamp: time.Now()},
		{CgroupID: 3, Action: "packet_observed", Timestamp: time.Now()},
	}
	b.Annotate(rows)

	if rows[0].DegradedReason != DegradedFQDNInactive {
		t.Fatalf("enforce row = %+v", rows[0])
	}

	if rows[1].DegradedReason != "" {
		t.Fatalf("audit row flagged: %+v", rows[1])
	}
}

func TestAnnotate_DNSPinPreBind(t *testing.T) {
	t.Parallel()

	r := newRig(WithBinderDNSUpstreams([]net.IP{net.ParseIP("10.96.0.10")}))
	p := enforcePol(1, "1.1.1.1")
	p.IPRules = append(p.IPRules, BuildIPRule{IP: "8.8.8.8", Port: 53, Allow: true, Prio: 5})
	r.src.set("g/a", "j", p)
	r.b.OnBind(1, exactBinding("g/a", "j"))

	rows := []Violation{
		{CgroupID: 1, IP: "10.96.0.10", Port: 53, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now()},
		{CgroupID: 1, IP: "8.8.8.8", Port: 53, EnforcementState: EnfStatePendingBind, Timestamp: r.clk.now()},
	}
	r.b.Annotate(rows)

	if rows[0].WouldBlock {
		t.Error("the configured upstream must pass the pin without any rule")
	}

	if !rows[1].WouldBlock {
		t.Error("port 53 to another resolver must be would_block even when a rule allows it")
	}
}

func TestAnnotate_HistoryDisconnectedFlag(t *testing.T) {
	t.Parallel()

	r := newRig(WithBinderHistory(func() bool { return true }, nil))
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: r.clk.now()}}
	r.b.Annotate(rows)

	if rows[0].BuildFlag != BuildFlagHistoryDisconnected {
		t.Fatalf("row = %+v", rows[0])
	}
}

func TestDecodeBKEvent_DNSv6AndLevel(t *testing.T) {
	t.Parallel()

	raw := make([]byte, minBKDropEventSize)
	copy(raw[0:4], []byte{8, 8, 8, 8})
	raw[4] = 53
	raw[16] = 7
	raw[15] = dropReasonDNSBypass
	raw[292] = bkVerdictDropped
	raw[293] = bkStateBound

	v, _, _ := decodeBKEvent(raw, time.Now())
	if v.Action != "dns_bypass_dropped" {
		t.Fatalf("action = %s", v.Action)
	}

	raw[0], raw[1], raw[2], raw[3] = 0, 0, 0, 0
	raw[15] = dropReasonIPv6
	raw[292] = bkVerdictWouldBlock

	v, _, _ = decodeBKEvent(raw, time.Now())
	if v.IP != "::" || v.Action != "would_block" {
		t.Fatalf("ipv6 event = %+v", v)
	}

	raw[293] = bkStateDegradedLevel
	raw[292] = bkVerdictObserved

	v, _, _ = decodeBKEvent(raw, time.Now())
	if v.EnforcementState != EnfStateDegradedLevel || v.DegradedReason != DegradedRunLevel {
		t.Fatalf("level-mismatch event = %+v", v)
	}

	// Annotate must not overwrite the state even when a decision exists.
	r := newRig()
	r.src.set("g/a", "j", enforcePol(1, "1.1.1.1"))
	r.b.OnBind(7, exactBinding("g/a", "j"))

	v.CgroupID = 7
	rows := []Violation{v}
	r.b.Annotate(rows)

	if rows[0].EnforcementState != EnfStateDegradedLevel {
		t.Fatalf("row = %+v", rows[0])
	}
}

func TestRegistry_RetiredLinkNeverLive(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(time.Minute)
	obs := newRecObserver()
	reg.SetBindingObserver(obs)

	at := time.Now()
	reg.linkCgroupRetired(3, CgroupBinding{SessionRef: "r", ContainerID: "c3"})

	if _, live := reg.LookupByCgroupID(3); live {
		t.Fatal("retired link visible as live")
	}

	if b, ok := reg.LookupForEvent(3, at); !ok || b.SessionRef != "r" {
		t.Fatalf("retired link not resolvable: %+v ok=%v", b, ok)
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()

	if len(obs.binds) != 0 {
		t.Fatal("observer told about a dead cgroup")
	}
}

var _ = policy.RulePriority
