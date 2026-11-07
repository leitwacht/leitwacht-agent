package enforcer

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

const testUpstreamIP = "198.51.100.7"

// startUpstream runs a UDP DNS server on loopback answering every A query
// with testUpstreamIP; it returns its address and a query counter.
func startUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}

	var n atomic.Int64

	started := make(chan struct{})

	srv := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)

		resp := new(dns.Msg)
		resp.SetReply(r)

		if r.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(testUpstreamIP).To4(),
			}}
		}

		_ = w.WriteMsg(resp)
	})}

	served := make(chan struct{})

	go func() {
		defer close(served)

		_ = srv.ActivateAndServe()
	}()

	<-started

	// Shutdown only after the server is up (it races ActivateAndServe
	// otherwise), then wait for the serve goroutine so none outlives the test.
	t.Cleanup(func() {
		_ = srv.Shutdown()
		_ = pc.Close()
		<-served
	})

	return pc.LocalAddr().String(), &n
}

type dnsRig struct {
	*binderRig
	d   *buildDNS
	up  string
	hit *atomic.Int64
}

func newDNSRig(t *testing.T, hold time.Duration) *dnsRig {
	t.Helper()

	up, hit := startUpstream(t)
	br := newRig()
	main := NewViolationRecorder(nil)

	d, err := newBuildDNS(BuildDNSConfig{
		Upstreams:            []string{up},
		ExpansionSuppression: ExpansionSuppressionOff,
		HoldWindow:           hold,
		PollInterval:         10 * time.Millisecond,
	}, quietLog(), br.dp, br.b, main, []uint64{1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	d.ctx, d.cancel = context.WithCancel(context.Background())
	t.Cleanup(d.cancel)

	return &dnsRig{binderRig: br, d: d, up: up, hit: hit}
}

// fqdnPolicy is an IP rule (prio 1) plus name rules at prio 2..: the
// positions the per-pod proxy would see in a composed list.
func fqdnPolicy(version int, mode BuildPolicyMode, rules ...BuildFQDNRule) BuildPolicy {
	p := enforcePol(version, "203.0.113.9")
	p.Mode = mode
	p.FQDNRules = rules

	return p
}

func allowRule(pattern string, prio uint32, ports ...int) BuildFQDNRule {
	return BuildFQDNRule{Pattern: pattern, Allow: true, Prio: prio, Ports: ports}
}

func denyRule(pattern string, prio uint32, resolution string) BuildFQDNRule {
	return BuildFQDNRule{Pattern: pattern, Allow: false, Prio: prio, Resolution: resolution}
}

func (r *dnsRig) query(id uint64, name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)

	return r.d.handle(m, DNSQueryContext{CgroupID: id, PID: 42, Comm: "wget"})
}

func answerA(resp *dns.Msg) []string {
	var out []string

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}

	return out
}

func isSinkhole(resp *dns.Msg) bool {
	a := answerA(resp)

	return len(a) == 1 && a[0] == SinkholeIPv4
}

func (r *dnsRig) slotOf(t *testing.T, id uint64) uint32 {
	t.Helper()

	p, ok := r.dp.cg(id)
	if !ok || p.State != bkStateBound {
		t.Fatalf("cgroup %d not bound: %+v ok=%v", id, p, ok)
	}

	return p.Slot
}

func TestBuildDNS_PerQueryPolicySelection(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "build", fqdnPolicy(1, BuildModeEnforce, allowRule("*.example.org", 2, 443)))
	r.src.set("g/b", "build", fqdnPolicy(1, BuildModeEnforce, allowRule("*.other.org", 2)))

	r.b.OnBind(100, exactBinding("g/a", "build"))
	r.b.OnBind(200, exactBinding("g/b", "build"))

	slotA, slotB := r.slotOf(t, 100), r.slotOf(t, 200)
	if slotA == slotB {
		t.Fatal("different projects share a slot")
	}

	// A's rule allows www.example.org: real answer, seeded in A's slot only.
	resp := r.query(100, "www.example.org")
	if got := answerA(resp); len(got) != 1 || got[0] != testUpstreamIP {
		t.Fatalf("allowed name answer = %v", got)
	}

	if prio, ok := r.dp.seed(slotA, testUpstreamIP+":443"); !ok || prio != 2 {
		t.Fatalf("slot A seed = %d, %v; want prio 2", prio, ok)
	}

	if _, ok := r.dp.seed(slotB, testUpstreamIP+":443"); ok {
		t.Fatal("A's resolution leaked into B's slot")
	}

	// The same name from B's RUN step matches nothing in B's rules: sinkhole.
	if resp = r.query(200, "www.example.org"); !isSinkhole(resp) {
		t.Fatalf("name outside B's rules should be sinkholed, got %v", answerA(resp))
	}

	if _, ok := r.dp.seed(slotB, testUpstreamIP+":443"); ok {
		t.Fatal("sinkholed name seeded")
	}

	// Default ports when the rule names none.
	if resp = r.query(200, "x.other.org"); len(answerA(resp)) != 1 {
		t.Fatal("B's allowed name not answered")
	}

	for _, p := range []string{"443", "80"} {
		if _, ok := r.dp.seed(slotB, testUpstreamIP+":"+p); !ok {
			t.Fatalf("default port %s not seeded", p)
		}
	}
}

func TestBuildDNS_ModeSemantics(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)

	rules := []BuildFQDNRule{
		denyRule("blocked.example.org", 2, policy.DenyResolutionSinkhole),
		denyRule("gone.example.org", 3, policy.DenyResolutionNXDomain),
		allowRule("*.example.org", 4, 443),
	}

	r.src.set("g/enf", "j", fqdnPolicy(1, BuildModeEnforce, rules...))
	r.src.set("g/shd", "j", fqdnPolicy(1, BuildModeShadow, rules...))
	r.src.set("g/aud", "j", fqdnPolicy(1, BuildModeAudit, rules...))

	r.b.OnBind(1, exactBinding("g/enf", "j"))
	r.b.OnBind(2, exactBinding("g/shd", "j"))
	r.b.OnBind(3, exactBinding("g/aud", "j"))
	r.b.OnBind(4, ambiguousBinding(StrengthAmbiguous, PolicyKey{"g/enf", "j"}, PolicyKey{"g/shd", "j"}))

	t.Run("enforce sinkhole", func(t *testing.T) {
		if resp := r.query(1, "blocked.example.org"); !isSinkhole(resp) {
			t.Fatalf("answer %v", answerA(resp))
		}
	})

	t.Run("enforce nxdomain", func(t *testing.T) {
		if resp := r.query(1, "gone.example.org"); resp.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode %d", resp.Rcode)
		}
	})

	t.Run("enforce unmatched sinkhole", func(t *testing.T) {
		if resp := r.query(1, "evil.net"); !isSinkhole(resp) {
			t.Fatalf("answer %v", answerA(resp))
		}
	})

	t.Run("shadow answers normally and records would_block", func(t *testing.T) {
		before := r.hit.Load()

		resp := r.query(2, "blocked.example.org")
		if got := answerA(resp); len(got) != 1 || got[0] != testUpstreamIP {
			t.Fatalf("shadow must answer for real, got %v", got)
		}

		if r.hit.Load() == before {
			t.Fatal("shadow did not forward")
		}

		resp = r.query(2, "evil.net")
		if got := answerA(resp); len(got) != 1 || got[0] != testUpstreamIP {
			t.Fatalf("shadow unmatched must answer for real, got %v", got)
		}

		if _, ok := r.dp.seed(r.slotOf(t, 2), testUpstreamIP+":443"); ok {
			t.Fatal("shadow seeded a would-be-denied name")
		}

		got := map[string]string{}

		for _, e := range r.d.DrainDNS() {
			if e.BuildProjectPath == "g/shd" {
				got[e.Domain] = e.Action
			}
		}

		if got["blocked.example.org"] != "dns_would_block" || got["evil.net"] != "dns_would_block" {
			t.Fatalf("shadow dns activity = %v", got)
		}
	})

	t.Run("shadow still seeds allowed names", func(t *testing.T) {
		r.query(2, "ok.example.org")

		if _, ok := r.dp.seed(r.slotOf(t, 2), testUpstreamIP+":443"); !ok {
			t.Fatal("shadow allow not seeded")
		}
	})

	t.Run("audit project passes and observes", func(t *testing.T) {
		resp := r.query(3, "blocked.example.org")
		if got := answerA(resp); len(got) != 1 || got[0] != testUpstreamIP {
			t.Fatalf("audit answer %v", got)
		}

		if _, ok := r.dp.seed(r.slotOf(t, 3), testUpstreamIP+":443"); ok {
			t.Fatal("audit seeded")
		}
	})

	t.Run("ambiguous passes", func(t *testing.T) {
		if resp := r.query(4, "evil.net"); len(answerA(resp)) != 1 || isSinkhole(resp) {
			t.Fatal("ambiguous cgroup must be answered normally")
		}
	})

	t.Run("unattributed query passes and goes to the shared recorder", func(t *testing.T) {
		if resp := r.query(0, "evil.net"); len(answerA(resp)) != 1 || isSinkhole(resp) {
			t.Fatal("unattributed query must be answered normally")
		}

		_, dnsEntries, _ := r.d.main.SnapshotAndReset()

		var seen bool

		for _, e := range dnsEntries {
			if e.Domain == "evil.net" && e.Action == "dns_observed" {
				seen = true
			}
		}

		if !seen {
			t.Fatalf("no dns_observed entry in %+v", dnsEntries)
		}
	})
}

func TestBuildDNS_HoldUntilBound(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, 2*time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("ok.example.org", 2, 443)))

	r.b.holdMu.Lock()
	r.b.holdOn = true
	r.b.holdMu.Unlock()

	// Not bound yet: the answer waits for the join, then follows policy
	// (a sinkhole for a name the policy does not allow).
	done := make(chan *dns.Msg, 1)

	go func() { done <- r.query(300, "evil.net") }()

	select {
	case <-done:
		t.Fatal("pending cgroup's query answered before the join")
	case <-time.After(150 * time.Millisecond):
	}

	r.b.OnBind(300, exactBinding("g/a", "j"))

	select {
	case resp := <-done:
		if !isSinkhole(resp) {
			t.Fatalf("held query not answered per the bound policy: %v", answerA(resp))
		}
	case <-time.After(time.Second):
		t.Fatal("held query not released by the bind")
	}
}

func TestBuildDNS_HoldDeadlinePassesInAudit(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, 250*time.Millisecond)

	r.b.holdMu.Lock()
	r.b.holdOn = true
	r.b.holdMu.Unlock()

	start := time.Now()
	resp := r.query(301, "evil.net") // never bound

	if el := time.Since(start); el < 200*time.Millisecond || el > 1500*time.Millisecond {
		t.Fatalf("held for %v, want about the 250ms window", el)
	}

	if got := answerA(resp); len(got) != 1 || got[0] != testUpstreamIP {
		t.Fatalf("never-bound cgroup must be answered in audit, got %v", got)
	}

	// A second query of the same cgroup is not held again.
	start = time.Now()
	r.query(301, "evil.net")

	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("deadline already passed for this cgroup; the query must not wait again")
	}
}

func TestBuildDNS_NoHoldWithoutEnforce(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, 2*time.Second)

	start := time.Now()
	r.query(302, "evil.net")

	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("audit/shadow-only deployments must not pay the hold latency")
	}
}

func TestBuildDNS_CarryForwardOnPolicyUpdate(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("*.example.org", 2, 443)))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	slot1 := r.slotOf(t, 1)

	r.query(1, "a.example.org")
	r.query(1, "b.other.net") // sinkholed, never seeded

	if _, ok := r.dp.seed(slot1, testUpstreamIP+":443"); !ok {
		t.Fatal("not seeded")
	}

	// v2: the allow moved down the list (prio 3, port 8443): the entry is
	// carried over re-prioritised, with the new rule's ports.
	r.src.set("g/a", "j", fqdnPolicy(2, BuildModeEnforce, denyRule("x.net", 2, ""), allowRule("*.example.org", 3, 8443)))
	r.b.OnPolicyChange("g/a")

	slot2 := r.slotOf(t, 1)
	if slot2 == slot1 {
		t.Fatal("cgroup not flipped to a new slot")
	}

	if prio, ok := r.dp.seed(slot2, testUpstreamIP+":8443"); !ok || prio != 3 {
		t.Fatalf("carried seed = %d, %v; want prio 3 on 8443", prio, ok)
	}

	if _, ok := r.dp.seed(slot2, testUpstreamIP+":443"); ok {
		t.Fatal("old rule's port carried over")
	}

	// v3: the name is now denied: nothing is carried.
	r.src.set("g/a", "j", fqdnPolicy(3, BuildModeEnforce, denyRule("a.example.org", 2, ""), allowRule("*.example.org", 3, 8443)))
	r.b.OnPolicyChange("g/a")

	slot3 := r.slotOf(t, 1)
	if _, ok := r.dp.seed(slot3, testUpstreamIP+":8443"); ok {
		t.Fatal("a name that is now denied was carried forward")
	}
}

func TestBuildDNS_FQDNInactiveFlagFollowsProxy(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("*.example.org", 2)))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	row := func() Violation {
		rows := []Violation{{CgroupID: 1, Action: "packet_observed", Timestamp: time.Now()}}
		r.b.Annotate(rows)

		return rows[0]
	}

	if row().DegradedReason != DegradedFQDNInactive {
		t.Fatal("rows must be flagged while the proxy is not active")
	}

	r.b.SetDNSProxyActive(true)

	if got := row().DegradedReason; got != "" {
		t.Fatalf("flag still set with the proxy active: %q", got)
	}

	r.b.SetDNSProxyActive(false)

	if row().DegradedReason != DegradedFQDNInactive {
		t.Fatal("flag must return when the proxy goes away")
	}
}

func TestBuildDNS_DomainOnRowsPerCgroup(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("*.example.org", 2)))
	r.b.OnBind(1, exactBinding("g/a", "j"))
	r.b.OnBind(2, exactBinding("g/a", "j"))

	r.query(1, "www.example.org")

	rows := []Violation{
		{CgroupID: 1, IP: testUpstreamIP, Port: 443},
		{CgroupID: 2, IP: testUpstreamIP, Port: 443}, // resolved by cgroup 1, not 2
		{CgroupID: 1, IP: "1.2.3.4", Port: 443},
		{CgroupID: 1, IP: testUpstreamIP, Domain: "kept.example", DomainSource: "x"},
	}

	r.d.StampDomains(rows)

	if rows[0].Domain != "www.example.org" || rows[0].DomainSource != DomainSourceBuildDNSProxy {
		t.Fatalf("row 0 = %+v", rows[0])
	}

	if rows[1].Domain != "" || rows[2].Domain != "" {
		t.Fatalf("domain stamped for an IP this cgroup did not resolve: %+v %+v", rows[1], rows[2])
	}

	if rows[3].Domain != "kept.example" {
		t.Fatal("existing domain overwritten")
	}
}

func TestBuildDNS_DrainCarriesProject(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "build", fqdnPolicy(1, BuildModeEnforce, allowRule("*.example.org", 2)))
	r.b.OnBind(1, exactBinding("g/a", "build"))

	r.query(1, "www.example.org")

	entries := r.d.DrainDNS()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v", entries)
	}

	e := entries[0]
	if e.Domain != "www.example.org" || e.Action != "dns_allowed" || e.BuildProjectPath != "g/a" || e.BuildJobName != "build" || e.PolicyKey == "" {
		t.Fatalf("entry = %+v", e)
	}

	if again := r.d.DrainDNS(); len(again) != 0 {
		t.Fatalf("drain did not reset: %+v", again)
	}
}

func TestSynthPolicyKeepsPriorities(t *testing.T) {
	t.Parallel()

	p := synthPolicy([]BuildFQDNRule{allowRule("a.example", 3), denyRule("b.example", 5, "")})
	rules := p.RulesForJob("")

	if len(rules) != 5 {
		t.Fatalf("list length %d, want 5", len(rules))
	}

	rule, idx, ok := matchFirstRule("a.example", rules)
	if !ok || policy.RulePriority(idx) != 3 || rule.Action != policy.ActionAllow {
		t.Fatalf("a.example -> idx %d ok %v", idx, ok)
	}

	if _, idx, ok = matchFirstRule("b.example", rules); !ok || policy.RulePriority(idx) != 5 {
		t.Fatalf("b.example -> idx %d ok %v", idx, ok)
	}
}

// ---- lifecycle ----

// lifeEnv fakes the host: which pid is in which netns and which RUN
// processes are alive.
type lifeEnv struct {
	mu    sync.Mutex
	pid   int    // operator source pid (0 = gone)
	ino   uint64 // operator source netns
	inoOf map[int]uint64
	procs []runSample
	binds int
}

func (e *lifeEnv) setProcs(p ...runSample) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.procs = p

	for _, s := range p {
		e.inoOf[s.pid] = s.ino
	}
}

// newRunRig is the production mode: netns from live RUN processes.
func newRunRig(t *testing.T) (*dnsRig, *lifeEnv) {
	t.Helper()

	r := newDNSRig(t, time.Second)
	env := &lifeEnv{inoOf: map[int]uint64{}}

	r.d.netnsInode = func(pid int) (uint64, error) {
		env.mu.Lock()
		defer env.mu.Unlock()

		if ino, ok := env.inoOf[pid]; ok {
			return ino, nil
		}

		return 0, errBuildDNSProcGone
	}
	r.d.bind = func(_ int, _ string) (net.PacketConn, net.Listener, error) {
		env.mu.Lock()
		defer env.mu.Unlock()

		env.binds++

		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}

		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			_ = pc.Close()

			return nil, nil, err
		}

		return pc, ln, nil
	}
	r.d.sample = func() []runSample {
		env.mu.Lock()
		defer env.mu.Unlock()

		return append([]runSample(nil), env.procs...)
	}
	r.d.anyInNetns = func(uint64) bool { return false } // fake inodes: never scan the real /proc
	r.d.cfg.Tracker = &fakeTracker{byTCP: map[uint16]uint64{}}

	t.Cleanup(func() {
		r.d.mu.Lock()
		r.d.unbindLocked("shutdown")
		r.d.mu.Unlock()
	})

	return r, env
}

// newLifeRig is newRunRig with an operator-supplied netns source.
func newLifeRig(t *testing.T) (*dnsRig, *lifeEnv) {
	t.Helper()

	r, env := newRunRig(t)
	env.pid, env.ino = 10, 1001
	env.inoOf[10] = 1001

	r.d.cfg.NetnsPID = func() (int, error) {
		env.mu.Lock()
		defer env.mu.Unlock()

		if env.pid == 0 {
			return 0, errBuildDNSProcGone
		}

		return env.pid, nil
	}
	r.d.netnsInode = func(pid int) (uint64, error) {
		env.mu.Lock()
		defer env.mu.Unlock()

		if pid == env.pid {
			return env.ino, nil
		}

		if ino, ok := env.inoOf[pid]; ok {
			return ino, nil
		}

		return 0, errBuildDNSProcGone
	}

	env.setProcs(runSample{pid: 10, ino: 1001})

	return r, env
}

func (r *dnsRig) redirectState() (bool, int) {
	r.dp.mu.Lock()
	defer r.dp.mu.Unlock()

	return r.dp.redirect, r.dp.redirectCall
}

func TestBuildDNS_SequentialStepsKeepProxyBound(t *testing.T) {
	t.Parallel()

	r, env := newRunRig(t)

	// Nothing alive yet: nothing to bind (and the redirect stays off).
	r.d.reconcile()

	if on, _ := r.redirectState(); on || r.d.proxy != nil {
		t.Fatal("bound with no RUN process and no trusted source")
	}

	// Step 1 starts: bind in its netns and enable.
	env.setProcs(runSample{pid: 100, ino: 5000})
	r.d.reconcile()

	if on, _ := r.redirectState(); !on || !r.b.DNSProxyActive() {
		t.Fatal("not active with a live RUN process")
	}

	// Steps end, gaps with no RUN process alive, then new steps in the
	// same netns: the proxy and the redirect never go away.
	for i := range 5 {
		env.setProcs()
		r.d.reconcile()

		if on, _ := r.redirectState(); !on || !r.b.DNSProxyActive() {
			t.Fatalf("gap %d: redirect dropped between steps", i)
		}

		env.setProcs(runSample{pid: 200 + i, ino: 5000})
		r.d.reconcile()
	}

	if env.binds != 1 {
		t.Fatalf("binds = %d, want 1 (no rebind between steps)", env.binds)
	}

	if _, calls := r.redirectState(); calls != 1 {
		t.Fatalf("redirect toggled %d times, want exactly one enable", calls)
	}
}

func TestBuildDNS_RestartRebindsOnProof(t *testing.T) {
	t.Parallel()

	r, env := newRunRig(t)

	env.setProcs(runSample{pid: 100, ino: 5000})
	r.d.reconcile()
	env.setProcs()
	r.d.reconcile()

	// buildkitd restarted into a new netns: the next step proves it.
	env.setProcs(runSample{pid: 300, ino: 6000})
	r.d.reconcile()

	if env.binds != 2 || r.d.boundIno != 6000 {
		t.Fatalf("binds=%d bound=%d, want a rebind into 6000", env.binds, r.d.boundIno)
	}

	if on, _ := r.redirectState(); !on || !r.b.DNSProxyActive() {
		t.Fatal("not active after the rebind")
	}
}

func TestBuildDNS_CNILatchesAndFlapLatches(t *testing.T) {
	t.Parallel()

	// Several netns alive at once: latch, redirect never on.
	r, env := newRunRig(t)
	env.setProcs(runSample{pid: 100, ino: 5000}, runSample{pid: 101, ino: 5001})
	r.d.reconcile()

	// first sample binds 5000 and is "from a RUN process"; the second
	// differs: latched, off.
	r.d.reconcile()

	if on, _ := r.redirectState(); on || r.b.DNSProxyActive() {
		t.Fatal("redirect on while RUN steps run in different netns")
	}

	// A flapping netns (one per step, never two at once) latches too.
	r2, env2 := newRunRig(t)

	for i := range maxProofRebinds + 2 {
		env2.setProcs(runSample{pid: 100 + i, ino: uint64(7000 + i)})
		r2.d.reconcile()
	}

	if !r2.d.mismatch {
		t.Fatal("rebind flap did not latch")
	}

	if on, _ := r2.redirectState(); on {
		t.Fatal("redirect on while latched")
	}

	if env2.binds > maxProofRebinds+1 {
		t.Fatalf("binds = %d: rebinding did not stop at the flap threshold", env2.binds)
	}

	// The latch expires.
	r2.d.mu.Lock()
	r2.d.latchUntil = time.Now().Add(-time.Second)
	r2.d.mu.Unlock()

	env2.setProcs(runSample{pid: 900, ino: r2.d.boundIno})
	r2.d.reconcile()

	if on, _ := r2.redirectState(); !on {
		t.Fatal("not re-enabled after the latch expired")
	}

	_ = env
}

func TestBuildDNS_UnverifiedBindStaysOff(t *testing.T) {
	t.Parallel()

	r, env := newLifeRig(t)

	// Operator source, but no RUN process has confirmed the netns yet.
	env.setProcs()
	r.d.reconcile()

	if on, calls := r.redirectState(); on || calls != 0 {
		t.Fatal("redirect enabled without a positive RUN-process netns match")
	}

	env.setProcs(runSample{pid: 10, ino: 1001})
	r.d.reconcile()

	if on, _ := r.redirectState(); !on {
		t.Fatal("not enabled after a RUN process confirmed the netns")
	}

	env.setProcs()
	r.d.reconcile()

	if on, _ := r.redirectState(); !on {
		t.Fatal("verified redirect must stay on between builds")
	}
}

func TestBuildDNS_OperatorSourceFollowsNetns(t *testing.T) {
	t.Parallel()

	r, env := newLifeRig(t)

	r.d.reconcile()

	if on, _ := r.redirectState(); !on || !r.b.DNSProxyActive() {
		t.Fatal("proxy not active")
	}

	if r.dp.redirectIP.String() != "127.0.0.153" || r.dp.redirectPort != 15354 {
		t.Fatalf("redirect target %s:%d", r.dp.redirectIP, r.dp.redirectPort)
	}

	r.d.reconcile()

	if env.binds != 1 {
		t.Fatalf("binds = %d after an unchanged reconcile", env.binds)
	}

	env.mu.Lock()
	env.pid, env.ino = 11, 2002
	env.mu.Unlock()
	env.setProcs(runSample{pid: 11, ino: 2002})

	r.d.reconcile()

	if env.binds != 2 {
		t.Fatalf("binds = %d, want a rebind", env.binds)
	}

	env.mu.Lock()
	env.pid = 0
	env.mu.Unlock()

	r.d.reconcile()

	if on, _ := r.redirectState(); on || r.b.DNSProxyActive() {
		t.Fatal("redirect/proxy still active with no buildkitd")
	}
}

func TestBuildDNS_DeadProxyClearsRedirectFirstThenRebinds(t *testing.T) {
	t.Parallel()

	r, env := newRunRig(t)

	env.setProcs(runSample{pid: 100, ino: 5000})
	r.d.reconcile()

	if on, _ := r.redirectState(); !on {
		t.Fatal("not active")
	}

	// Kill the serving goroutines from under it.
	r.d.mu.Lock()
	_ = r.d.proxy.udpConn.Close()
	r.d.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for r.d.proxy.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	r.dp.mu.Lock()
	r.dp.redirectLog = nil
	r.dp.mu.Unlock()

	r.d.reconcile()

	r.dp.mu.Lock()
	log := append([]bool(nil), r.dp.redirectLog...)
	r.dp.mu.Unlock()

	if len(log) < 2 || log[0] != false || log[len(log)-1] != true {
		t.Fatalf("redirect calls %v: want cleared first, then re-enabled after the rebind", log)
	}

	if env.binds != 2 || !r.d.proxy.Alive() {
		t.Fatalf("binds=%d alive=%v, want a fresh live proxy", env.binds, r.d.proxy.Alive())
	}
}

func TestBuildDNS_LateNameAfterReseedIsSeeded(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("late.example.org", 2, 443)))
	r.b.OnBind(80, exactBinding("g/a", "j"))
	r.d.reseedBound() // sets seeded[80]; nothing recorded yet

	// A query that decided before the bind (stale non-enforcing decision)
	// finishes after the reseed ran: the name must still be seeded.
	m := new(dns.Msg)
	m.SetQuestion("late.example.org.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(m)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "late.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(testUpstreamIP).To4(),
	}}

	r.d.afterAnswer(BuildDNSDecision{}, 80, m, resp)

	if _, ok := r.dp.seed(r.slotOf(t, 80), testUpstreamIP+":443"); !ok {
		t.Fatal("name recorded after the reseed was never seeded")
	}
}

func TestBuildDNS_NetnsSourceIgnoresSpoofedComm(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	proc := func(pid, comm, cgroup string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroup+"\n"), 0o644)
	}

	const uid = "12345678-1234-1234-1234-123456789abc"

	// A job pod runs its own "buildkitd": same comm, lower PID, wrong cgroup.
	proc("5", "buildkitd", "/kubepods/job-pod/ctr")
	proc("9", "buildkitd", "/kubepods/pod"+strings.ReplaceAll(uid, "-", "_")+"/ctr")

	if _, err := findTrustedProc(root, "buildkitd", "/kubepods/other"); err == nil {
		t.Fatal("a comm match without the configured cgroup was accepted")
	}

	for _, want := range []string{uid, "/kubepods/pod" + strings.ReplaceAll(uid, "-", "_")} {
		if pid, err := findTrustedProc(root, "buildkitd", want); err != nil || pid != 9 {
			t.Fatalf("%q: pid %d err %v, want 9 (cgroup-matched, not the spoofed lower PID)", want, pid, err)
		}
	}

	for _, bad := range []string{"pod", "kubepods", "12345678", "../x"} {
		if validateProcCgroup(bad) == nil {
			t.Fatalf("%q accepted as a cgroup identifier", bad)
		}
	}

	if validateProcCgroup(uid) != nil || validateProcCgroup("/kubepods/podx") != nil || validateProcCgroup("") != nil {
		t.Fatal("valid identifier rejected")
	}

	// With nothing configured, comm alone never yields a pid; a RUN-cgroup
	// process does.
	r := newDNSRig(t, time.Second)
	r.d.cfg.ProcRoot = root

	if p, _ := r.d.candidatePID(nil); p != 0 {
		t.Fatalf("candidate %d from a comm match alone", p)
	}

	r.d.cfg.ProcCgroupContains = uid

	if p, fromRun := r.d.candidatePID(nil); p != 9 || fromRun {
		t.Fatalf("candidate %d fromRun=%v, want the cgroup-matched 9, unverified", p, fromRun)
	}

	run := filepath.Join(root, "parent", "run-1")
	_ = os.MkdirAll(run, 0o755)
	_ = os.WriteFile(filepath.Join(run, "cgroup.procs"), []byte("77\n"), 0o644)

	if got := runProcs([]string{filepath.Join(root, "parent")}, 4); len(got) != 1 || got[0] != 77 {
		t.Fatalf("runProcs = %v", got)
	}
}

func TestBuildDNS_PerCgroupLimits(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)

	// Rate: a flood from one cgroup gets REFUSED, another cgroup is untouched.
	refused := 0

	for range 2 * int(queryBurst) {
		if resp := r.query(900, "flood.example"); resp.Rcode == dns.RcodeRefused {
			refused++
		}
	}

	if refused == 0 {
		t.Fatal("no query refused for a flooding cgroup")
	}

	if resp := r.query(901, "other.example"); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("other cgroup affected by the flood: rcode %d", resp.Rcode)
	}

	// In-flight cap.
	var rel []func()

	for range maxInflightPerCgroup {
		f, ok := r.d.admit(902)
		if !ok {
			t.Fatal("refused below the in-flight cap")
		}

		rel = append(rel, f)
	}

	if _, ok := r.d.admit(902); ok {
		t.Fatal("in-flight cap not enforced")
	}

	if f, ok := r.d.admit(903); !ok {
		t.Fatal("another cgroup refused by 902's in-flight queries")
	} else {
		f()
	}

	for _, f := range rel {
		f()
	}

	if _, ok := r.d.admit(902); !ok {
		t.Fatal("not admitted again after release")
	}
}

func TestBuildDNS_HoldsPerCgroupCapped(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, 600*time.Millisecond)

	r.b.holdMu.Lock()
	r.b.holdOn = true
	r.b.holdMu.Unlock()

	var wg sync.WaitGroup

	slow := atomic.Int64{}
	start := time.Now()

	for range maxHoldsPerCgroup + 6 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			r.query(950, "evil.net")

			if time.Since(start) > 400*time.Millisecond {
				slow.Add(1)
			}
		}()
	}

	wg.Wait()

	if n := slow.Load(); n > maxHoldsPerCgroup {
		t.Fatalf("%d queries held for one cgroup, cap is %d", n, maxHoldsPerCgroup)
	}
}

func TestBuildDNS_LateBindReseeds(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("ok.example.org", 2, 443)))

	// Resolved while unbound (hold timed out / overflowed): answered, not seeded.
	if resp := r.query(70, "ok.example.org"); len(answerA(resp)) != 1 {
		t.Fatal("unbound query not answered")
	}

	r.b.OnBind(70, exactBinding("g/a", "j"))

	slot := r.slotOf(t, 70)
	if _, ok := r.dp.seed(slot, testUpstreamIP+":443"); ok {
		t.Fatal("seeded before the reseed")
	}

	r.d.reseedBound()

	if prio, ok := r.dp.seed(slot, testUpstreamIP+":443"); !ok || prio != 2 {
		t.Fatalf("late bind not reseeded: %d %v", prio, ok)
	}
}

func TestBuildDNS_BindFailureStaysInactive(t *testing.T) {
	t.Parallel()

	r, _ := newLifeRig(t)

	r.d.bind = func(int, string) (net.PacketConn, net.Listener, error) {
		return nil, nil, errBuildDNSProcGone
	}

	r.d.reconcile()

	if on, calls := r.redirectState(); on || calls != 0 || r.b.DNSProxyActive() {
		t.Fatal("redirect touched although the proxy could not bind")
	}
}

// TestBuildDNS_ProxyServesAttributedQueries runs the real DNSProxy on
// loopback sockets with a fake tracker and checks that the attribution
// from the tracker selects the policy.
type fakeTracker struct {
	mu    sync.Mutex
	byTCP map[uint16]uint64
	added []uint64
	rm    []uint64
}

func (f *fakeTracker) AddRunParent(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.added = append(f.added, id)

	return nil
}

func (f *fakeTracker) RemoveRunParent(id uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.rm = append(f.rm, id)
}

func (f *fakeTracker) LookupWithBinary(_ uint64, port uint16) (uint32, string, string, string, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if id, ok := f.byTCP[port]; ok {
		return 7, "wget", "sh", "/bin/wget", id
	}

	return 0, "", "", "", 0
}

func TestBuildDNS_ProxyEndToEnd(t *testing.T) {
	t.Parallel()

	r, _ := newLifeRig(t)
	tr, _ := r.d.cfg.Tracker.(*fakeTracker)

	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("ok.example.org", 2, 443)))
	r.b.OnBind(5, exactBinding("g/a", "j"))

	r.d.reconcile()

	t.Cleanup(func() {
		r.d.mu.Lock()
		r.d.unbindLocked("shutdown")
		r.d.mu.Unlock()
	})

	r.d.mu.Lock()
	addr := r.d.proxy.udpConn.LocalAddr().String()
	r.d.mu.Unlock()

	ask := func(name string) *dns.Msg {
		c, err := net.Dial("udp4", addr)
		if err != nil {
			t.Fatal(err)
		}

		defer c.Close() //nolint:errcheck // test

		_, portStr, _ := net.SplitHostPort(c.LocalAddr().String())
		port, _ := strconv.Atoi(portStr)

		tr.mu.Lock()
		tr.byTCP[uint16(port)] = 5 //nolint:gosec // test port
		tr.mu.Unlock()

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)

		co := &dns.Conn{Conn: c}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))

		if err = co.WriteMsg(m); err != nil {
			t.Fatal(err)
		}

		resp, err := co.ReadMsg()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		return resp
	}

	if resp := ask("ok.example.org"); len(answerA(resp)) != 1 || isSinkhole(resp) {
		t.Fatalf("allowed name over the wire: %v", answerA(resp))
	}

	slot := r.slotOf(t, 5)
	if _, ok := r.dp.seed(slot, testUpstreamIP+":443"); !ok {
		t.Fatal("not seeded through the proxy")
	}

	if resp := ask("evil.net"); !isSinkhole(resp) {
		t.Fatalf("unlisted name over the wire: %v", answerA(resp))
	}
}

func TestBuildDNS_InactiveFlagIsRecordTime(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)
	r.src.set("g/a", "j", fqdnPolicy(1, BuildModeEnforce, allowRule("*.example.org", 2)))
	r.b.OnBind(1, exactBinding("g/a", "j"))

	down := Violation{CgroupID: 1, Action: "packet_observed", Timestamp: time.Now()}

	time.Sleep(5 * time.Millisecond)
	r.b.SetDNSProxyActive(true)
	time.Sleep(5 * time.Millisecond)

	up := Violation{CgroupID: 1, Action: "packet_observed", Timestamp: time.Now()}
	rows := []Violation{down, up}

	r.b.Annotate(rows) // flushed while the proxy is up

	if rows[0].DegradedReason != DegradedFQDNInactive {
		t.Fatal("row recorded while the proxy was down lost its flag at flush time")
	}

	if rows[1].DegradedReason != "" {
		t.Fatal("row recorded while the proxy was up flagged")
	}
}

func TestBuildDNS_ForeignAloneNeedsOldNetnsEmpty(t *testing.T) {
	t.Parallel()

	r, env := newRunRig(t)

	env.setProcs(runSample{pid: 100, ino: 5000})
	r.d.reconcile()
	env.setProcs()
	r.d.reconcile()

	// A RUN step alone in another netns (unshare -n) while processes remain
	// in the bound one (the real buildkitd): no rebind, redirect untouched.
	r.d.anyInNetns = func(uint64) bool { return true }

	for i := range 10 {
		env.setProcs(runSample{pid: 300 + i, ino: uint64(9000 + i)})
		r.d.reconcile()
	}

	if env.binds != 1 || r.d.boundIno != 5000 || r.d.mismatch {
		t.Fatalf("binds=%d bound=%d latched=%v: a foreign netns with the old one still in use must not rebind", env.binds, r.d.boundIno, r.d.mismatch)
	}

	if on, _ := r.redirectState(); !on {
		t.Fatal("redirect dropped by a foreign-netns step")
	}

	// Nobody left in the old netns: a genuine restart, rebind.
	r.d.anyInNetns = func(uint64) bool { return false }

	env.setProcs(runSample{pid: 400, ino: 6000})
	r.d.reconcile()

	if env.binds != 2 || r.d.boundIno != 6000 {
		t.Fatalf("binds=%d bound=%d, want a rebind into 6000", env.binds, r.d.boundIno)
	}
}

type loopDialer struct {
	mu     sync.Mutex
	target string
}

func (l *loopDialer) DialUDP(string, int) (*net.UDPConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, err := net.ResolveUDPAddr("udp4", l.target)
	if err != nil {
		return nil, err
	}

	return net.DialUDP("udp4", nil, a)
}

func (l *loopDialer) DialTCP(string, int) (net.Conn, error) { return nil, errBuildDNSProcGone }
func (l *loopDialer) Close() error                          { return nil }

func TestBuildDNS_LivenessProbeClearsAndRebinds(t *testing.T) {
	t.Parallel()

	r, env := newRunRig(t)
	ld := &loopDialer{}
	r.d.newDialer = func(int) (UpstreamDialer, error) { return ld, nil }

	env.setProcs(runSample{pid: 100, ino: 5000})
	r.d.reconcile()

	r.d.mu.Lock()
	ld.target = r.d.proxy.udpConn.LocalAddr().String()
	r.d.mu.Unlock()

	if !r.d.probeOnce() {
		t.Fatal("probe failed against a healthy proxy")
	}

	if on, _ := r.redirectState(); !on {
		t.Fatal("healthy proxy lost its redirect")
	}

	// The listener stops answering (here: the probe's path goes to a dead
	// port): redirect cleared first, proxy unbound.
	ld.mu.Lock()
	ld.target = "127.0.0.1:1"
	ld.mu.Unlock()

	r.dp.mu.Lock()
	r.dp.redirectLog = nil
	r.dp.mu.Unlock()

	if r.d.probeOnce() {
		t.Fatal("probe succeeded against a dead listener")
	}

	r.dp.mu.Lock()
	log := append([]bool(nil), r.dp.redirectLog...)
	r.dp.mu.Unlock()

	if len(log) == 0 || log[0] != false || r.d.proxy != nil || r.b.DNSProxyActive() {
		t.Fatalf("redirect log %v proxy=%v: want it cleared and unbound", log, r.d.proxy)
	}

	// The next step's reconcile rebinds.
	env.setProcs(runSample{pid: 101, ino: 5000})
	r.d.reconcile()

	if on, _ := r.redirectState(); !on || env.binds != 2 {
		t.Fatalf("not rebound: on=%v binds=%d", on, env.binds)
	}
}

func TestBuildDNS_PerProjectInflightCap(t *testing.T) {
	t.Parallel()

	r := newDNSRig(t, time.Second)

	var rel []func()

	for range maxInflightPerProject {
		f, ok := r.d.admitProject("g/a")
		if !ok {
			t.Fatal("refused below the project cap")
		}

		rel = append(rel, f)
	}

	if _, ok := r.d.admitProject("g/a"); ok {
		t.Fatal("project cap not enforced")
	}

	if f, ok := r.d.admitProject("g/b"); !ok {
		t.Fatal("another project starved by g/a")
	} else {
		f()
	}

	// Unbound steps (project "") are never refused by this cap.
	for range 3 * maxInflightPerProject {
		if _, ok := r.d.admitProject(""); !ok {
			t.Fatal("unbound/unattributed steps refused by the per-project cap")
		}
	}

	rel[0]()

	if _, ok := r.d.admitProject("g/a"); !ok {
		t.Fatal("not admitted after release")
	}
}
