package enforcer

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// chanSource is a CgroupEventSource fed by the test.
type chanSource struct{ in chan CgroupCreateEvent }

func (s *chanSource) Run(ctx context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) error {
	defer close(creates)
	defer close(removes)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-s.in:
			creates <- e
		}
	}
}

// A new RUN cgroup binds the proxy at once, with the poll loop not running
// at all, even though its first process shows up a moment after the mkdir.
func TestBuildDNS_RunCgroupEventBindsBeforePoll(t *testing.T) {
	t.Parallel()

	r, env := newRunRig(t)
	src := &chanSource{in: make(chan CgroupCreateEvent, 1)}
	root := t.TempDir()

	r.d.runPaths = []string{root}
	r.d.newSource = func([]string) CgroupEventSource { return src }
	r.d.watchDone = make(chan struct{})

	go r.d.watchRunCgroups()

	t.Cleanup(func() {
		r.d.cancel()
		<-r.d.watchDone
	})

	if r.d.Active() {
		t.Fatal("active before any RUN cgroup")
	}

	cg := filepath.Join(root, "run-1")
	if err := os.Mkdir(cg, 0o750); err != nil {
		t.Fatal(err)
	}

	src.in <- CgroupCreateEvent{CgroupPath: cg}

	// runc adds the first process after the cgroup exists.
	time.Sleep(20 * time.Millisecond)

	env.setProcs(runSample{pid: 4242, ino: 7001})

	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(4242)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)

	for !r.d.Active() {
		if time.Now().After(deadline) {
			t.Fatal("proxy not bound by the cgroup event")
		}

		time.Sleep(5 * time.Millisecond)
	}

	env.mu.Lock()
	defer env.mu.Unlock()

	if env.binds != 1 {
		t.Fatalf("binds = %d, want 1", env.binds)
	}
}

// DNS activity recorded while a cgroup had no policy is re-homed to the
// policy the cgroup was bound to before the flush; one still unbound is
// held for the grace period, then emitted unattributed (never dropped).
func TestBuildDNS_PendingActivityRehomedAtDrain(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Millisecond)
	r.src.set("g/p", "j", fqdnPolicy(1, BuildModeAudit))

	r.query(5, "pending.example.org")
	r.query(6, "never-bound.example.org")

	r.b.OnBind(5, exactBinding("g/p", "j"))

	got := map[string]DNSActivityEntry{}

	for _, e := range r.d.DrainDNS() {
		got[e.Domain] = e
	}

	if e, ok := got["pending.example.org"]; !ok || e.BuildProjectPath != "g/p" || e.BuildJobName != "j" || e.PolicyKey == "" {
		t.Fatalf("bound-before-flush entry not re-homed: %+v", got)
	}

	if _, ok := got["never-bound.example.org"]; ok {
		t.Fatalf("unbound entry emitted before the grace period: %+v", got)
	}

	if _, e, _ := r.d.main.SnapshotAndReset(); len(e) != 0 {
		t.Fatalf("pending queries leaked into the shared recorder: %+v", e)
	}

	// Past the grace period the still-unbound entry is emitted unstamped.
	r.d.mu.Lock()
	r.d.pend[6].since = time.Now().Add(-2 * pendingRehomeGrace)
	r.d.mu.Unlock()

	got = map[string]DNSActivityEntry{}

	for _, e := range r.d.DrainDNS() {
		got[e.Domain] = e
	}

	if e, ok := got["never-bound.example.org"]; !ok || e.BuildProjectPath != "" {
		t.Fatalf("unbound entry dropped or stamped: %+v", got)
	}

	// Emptied recorders are released.
	r.d.DrainDNS()
	r.d.DrainDNS()

	r.d.mu.Lock()
	n := len(r.d.pend)
	r.d.mu.Unlock()

	if n != 0 {
		t.Fatalf("pending recorders not released: %d", n)
	}
}

// At shutdown the final drain emits pending entries without waiting.
func TestBuildDNS_PendingActivityFlushedAtShutdown(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Millisecond)

	r.query(9, "late.example.org")
	r.d.cancel()

	var seen bool

	for _, e := range r.d.DrainDNS() {
		if e.Domain == "late.example.org" {
			seen = true
		}
	}

	if !seen {
		t.Fatal("pending entry lost at shutdown")
	}
}

// Short steps are removed (unbound) before the flush: their records are
// still stamped with the policy they had.
func TestBuildDNS_PendingRehomedAfterCgroupRemoved(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Millisecond)
	r.src.set("g/p", "j", fqdnPolicy(1, BuildModeAudit))

	r.clk.t = time.Now() // the binder's clock is the wall clock in production

	r.query(5, "short.example.org")
	r.b.OnBind(5, exactBinding("g/p", "j"))
	r.b.OnUnbind(5)

	if d := r.b.DNSDecision(5); d.Known {
		t.Fatal("cgroup still live; test premise broken")
	}

	var got *DNSActivityEntry

	for _, e := range r.d.DrainDNS() {
		if e.Domain == "short.example.org" {
			e := e
			got = &e
		}
	}

	if got == nil || got.BuildProjectPath != "g/p" || got.BuildJobName != "j" {
		t.Fatalf("record of a removed step not re-homed: %+v", got)
	}
}

// A drain between the query start and its answer must not orphan the
// recorder the late record is written to.
func TestBuildDNS_PendingRecorderKeptWhileInflight(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Millisecond)

	rec, release := r.d.pendingFor(11)
	if rec == r.d.main {
		t.Fatal("expected a pending recorder")
	}

	if out := r.d.DrainDNS(); len(out) != 0 {
		t.Fatalf("unexpected entries %+v", out)
	}

	r.d.cancel() // final: everything is eligible

	r.d.DrainDNS()

	rec.RecordDNS("late.example.org", "A", "dns_observed", nil, 1, "x", "", "")
	release()

	var seen bool

	for _, e := range r.d.DrainDNS() {
		if e.Domain == "late.example.org" {
			seen = true
		}
	}

	if !seen {
		t.Fatal("late record landed in an orphaned recorder")
	}
}

// Past the per-recorder entry cap, activity moves to the shared recorder.
func TestBuildDNS_PendingEntryCapOverflowsToMain(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Millisecond)

	rec, release := r.d.pendingFor(12)
	for i := 0; i < maxPendingEntries; i++ {
		rec.RecordDNS("h"+strconv.Itoa(i)+".example.org", "A", "dns_observed", nil, 1, "x", "", "")
	}

	release()

	if next, rel := r.d.pendingFor(12); next != r.d.main {
		t.Fatal("over the cap must use the shared recorder")
	} else {
		rel()
	}
}

// Close racing a cgroup event must not leave the proxy bound.
func TestBuildDNS_CloseRacingEventDoesNotRebind(t *testing.T) {
	t.Parallel()

	for i := 0; i < 20; i++ {
		r, env := newRunRig(t)
		src := &chanSource{in: make(chan CgroupCreateEvent, 1)}
		root := t.TempDir()

		cg := filepath.Join(root, "run-1")
		if err := os.Mkdir(cg, 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte("4242\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		env.setProcs(runSample{pid: 4242, ino: 7001})

		r.d.runPaths = []string{root}
		r.d.newSource = func([]string) CgroupEventSource { return src }
		r.d.cfg.Tracker = &fakeTracker{byTCP: map[uint16]uint64{}}
		r.d.parents = nil

		r.d.start(context.Background())

		src.in <- CgroupCreateEvent{CgroupPath: cg}

		r.d.Close()

		if r.d.Active() {
			t.Fatal("redirect on after Close")
		}

		r.d.mu.Lock()
		bound := r.d.proxy != nil
		r.d.mu.Unlock()

		if bound {
			t.Fatal("proxy bound after Close")
		}
	}
}

// A step that rewrites its resolv.conf search list cannot hide its own
// lookups: an expansion under a non-cluster suffix is still recorded.
func TestBuildDNS_StepControlledSearchListCannotHideRecords(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Millisecond)
	r.d.cfg.ExpansionSuppression = ExpansionSuppressionStructural
	r.d.auditCfg = r.d.newCfg(nil, false)
	r.d.search = []string{"attacker.example"}

	r.query(0, "payload.evil.com.attacker.example")

	_, entries, _ := r.d.main.SnapshotAndReset()

	var seen bool

	for _, e := range entries {
		if e.Domain == "payload.evil.com.attacker.example" {
			seen = true
		}
	}

	if !seen {
		t.Fatalf("lookup hidden by a step-controlled search list: %+v", entries)
	}
}
