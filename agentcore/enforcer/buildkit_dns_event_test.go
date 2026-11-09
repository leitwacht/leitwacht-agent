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
