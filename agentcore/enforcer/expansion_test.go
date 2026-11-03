package enforcer

import (
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

var testSearch = []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local", "ec2.internal", "dns.podman"}

func TestParseSearchList(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("# filler line to pad the file out\n", 200)

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"kubelet", "search ns.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.0.0.10\noptions ndots:5\n",
			[]string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local"}},
		{"ndots and options ignored", "nameserver 1.1.1.1\noptions ndots:5 timeout:1\nsearch a.test\n", []string{"a.test"}},
		{"domain line", "domain Corp.Test.\n", []string{"corp.test"}},
		{"domain takes first only", "domain a.test b.test\n", []string{"a.test"}},
		{"last directive wins", "search a.test\ndomain b.test\n", []string{"b.test"}},
		{"search after domain", "domain a.test\nsearch b.test c.test\n", []string{"b.test", "c.test"}},
		{"trailing dots and case", "SEARCH Foo.Test. BAR.test\n", []string{"foo.test", "bar.test"}},
		{"cap at six", "search a b c d e f g h\n", []string{"a", "b", "c", "d", "e", "f"}},
		{"comment tail", "search a.test # b.test\n", []string{"a.test"}},
		{"no search line", "nameserver 1.1.1.1\noptions ndots:2\n", nil},
		{"empty", "", nil},
		{"directive without args", "search\n", nil},
		{"truncated tail line dropped", long + "search a.test b.test", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseSearchList([]byte(tc.in))
			if !reflect.DeepEqual(got, tc.want) && (len(got) != 0 || len(tc.want) != 0) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSearchList_ReadCapKeepsEarlierLines(t *testing.T) {
	t.Parallel()

	in := "search a.test\n" + strings.Repeat("# pad\n", 1000) + "search evil.test\n"

	if got := parseSearchList([]byte(in)); !reflect.DeepEqual(got, []string{"a.test"}) {
		t.Fatalf("got %v, want the pre-cap search line only", got)
	}
}

func TestExpansionBases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		qname string
		want  []string
	}{
		{"redis.ns.svc.cluster.local", []string{"redis", "redis.ns", "redis.ns.svc"}},
		{"github.com.dns.podman", []string{"github.com"}},
		{"github.com", nil},
		{"cluster.local", nil},
		{"xcluster.local", nil}, // label boundary
		{"x.other.test", nil},
	}

	for _, tc := range cases {
		got := expansionBases(tc.qname, testSearch)
		sort.Strings(got)
		sort.Strings(tc.want)

		if !reflect.DeepEqual(got, tc.want) && (len(got) != 0 || len(tc.want) != 0) {
			t.Errorf("%s: got %v, want %v", tc.qname, got, tc.want)
		}
	}

	if got := expansionBases("a.cluster.local", nil); got != nil {
		t.Fatalf("empty list must give no bases, got %v", got)
	}
}

func TestPublicLookingDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"registry.gitlab.com":    true,
		"example.co.uk":          true, // multi-part ICANN suffix
		"EXAMPLE.Co.UK.":         true, // case and trailing dot
		"foo.appspot.com":        true, // private suffix counts as public
		"example.xn--p1ai":       true, // punycode TLD
		"redis":                  false,
		"web-0.db":               false,
		"svc.ns":                 false,
		"foo.local":              false, // .local is not in the list
		"foo.internal":           false,
		"co.uk":                  false, // a suffix, not a domain
		"com":                    false,
		"":                       false,
		"example.рф":             false, // raw non-ASCII never matches (fails toward "not noise")
		"registry.gitlab.com.ns": false,
	}

	for in, want := range cases {
		if got := publicLookingDomain(in); got != want {
			t.Errorf("publicLookingDomain(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsResolverNoise_StructuralCandidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		qname string
		list  []string
		want  bool
	}{
		{"registry.gitlab.com.ns.svc.cluster.local", []string{"ns.svc.cluster.local"}, true},
		{"registry.gitlab.com.ns.svc.cluster.local", testSearch, true},
		{"redis.ns.svc.cluster.local", testSearch, false},
		{"web-0.db.ns.svc.cluster.local", testSearch, false},
		{"registry.gitlab.com.ec2.internal", testSearch, true},
		{"example.co.uk.ns.svc.cluster.local", testSearch, true},
		{"foo.local.ns.svc.cluster.local", testSearch, false},
		{"evil.com.ns.svc.cluster.local", testSearch, true},    // crafted: still noise
		{"EVIL.COM.Team.Svc.Cluster.Local", testSearch, false}, // caller lowercases first; raw mixed case does not match
		{"registry.gitlab.com.ns.svc.cluster.local", nil, false},
		{"registry.gitlab.com.ns.svc.cluster.local", []string{"other.test"}, false},
		{"registry.gitlab.com", testSearch, false}, // not an expansion at all
		{"example.xn--p1ai.dns.podman", testSearch, true},
	}

	for _, tc := range cases {
		if got := isResolverNoise(tc.qname, tc.list); got != tc.want {
			t.Errorf("isResolverNoise(%q, %v) = %v, want %v", tc.qname, tc.list, got, tc.want)
		}
	}
}

// noiseHarness counts upstream contacts and lets each test decide how the
// fake upstream answers.
type noiseHarness struct {
	cfg      *DNSProxyConfig
	pol      *policy.ResolvedPolicy
	rec      *ViolationRecorder
	upstream atomic.Int32
	kills    atomic.Int32
	// answer returns the rcode and whether to include an A record; the
	// default is NXDOMAIN for in-cluster/search-suffix names, else an A record.
	answerMu sync.RWMutex
	answer   func(name string) (rcode int, withA bool)
	extraRR  func(name string) []dns.RR
}

func (h *noiseHarness) setRR(f func(string) []dns.RR) {
	h.answerMu.Lock()
	h.extraRR = f
	h.answerMu.Unlock()
}

func (h *noiseHarness) setAnswer(f func(string) (int, bool)) {
	h.answerMu.Lock()
	h.answer = f
	h.answerMu.Unlock()
}

func defaultAnswer(name string) (int, bool) {
	for _, suf := range []string{".cluster.local", ".ec2.internal", ".dns.podman"} {
		if strings.HasSuffix(name, suf) {
			return dns.RcodeNameError, false
		}
	}

	return dns.RcodeSuccess, true
}

func newNoiseHarness(t *testing.T, action string, rules []policy.Rule, search []string) *noiseHarness {
	t.Helper()

	cfg, pol, rec := testDNSConfig(action, rules)
	h := &noiseHarness{cfg: cfg, pol: pol, rec: rec, answer: defaultAnswer}

	cfg.SearchListFor = func(uint64) []string { return search }
	cfg.OnDNSViolation = func(uint64, string, string) { h.kills.Add(1) }

	up := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		h.upstream.Add(1)

		name := strings.TrimSuffix(q.Question[0].Name, ".")
		h.answerMu.RLock()
		answer, extra := h.answer, h.extraRR
		h.answerMu.RUnlock()

		rcode, withA := answer(name)

		r := replyTo(q, q.Id)
		r.Rcode = rcode

		if withA {
			r.Answer = []dns.RR{aRR(name, fakeUpstreamIP)}
		}

		if extra != nil {
			r.Answer = append(r.Answer, extra(name)...)
		}

		return []*dns.Msg{r}
	})
	cfg.DockerUDPDial = up.dialUDP
	cfg.DockerTCPDial = up.dialTCP

	return h
}

func (h *noiseHarness) query(name string) *dns.Msg {
	return HandleDNSQuery(makeQuery(name, dns.TypeA), h.cfg, h.pol, h.rec, 0, "", "", "", 7)
}

func (h *noiseHarness) recorded() []string {
	_, act := h.rec.Snapshot()

	out := make([]string, 0, len(act))
	for _, a := range act {
		out = append(out, a.Domain+"/"+a.Action)
	}

	sort.Strings(out)

	return out
}

var clusterDeny = []policy.Rule{denyFQDN("*.cluster.local", policy.DenyResolutionNXDomain)}

func TestNoise_ClusterNXDOMAIN_SynthesizedSilently_BothModes(t *testing.T) {
	for _, mode := range []string{"block", "audit"} {
		t.Run(mode, func(t *testing.T) {
			h := newNoiseHarness(t, mode, clusterDeny, testSearch)

			for i, n := range []string{
				"registry.gitlab.com.ns.svc.cluster.local",
				"evil.com.ns.svc.cluster.local", // crafted, but the cluster DNS says it does not exist
				"example.co.uk.svc.cluster.local",
			} {
				resp := h.query(n)
				if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 || len(resp.Ns) != 0 || len(resp.Extra) != 0 {
					t.Fatalf("%s: want a bare synthesized NXDOMAIN, got %v", n, resp)
				}

				if got := h.upstream.Load(); int(got) != i+1 {
					t.Fatalf("%s: upstream queries = %d, want exactly one per query", n, got)
				}
			}

			if got := h.recorded(); len(got) != 0 {
				t.Fatalf("noise recorded events: %v", got)
			}

			if h.kills.Load() != 0 {
				t.Fatal("noise must never call OnDNSViolation")
			}
		})
	}
}

// NXDOMAIN carrying a CNAME chain (ExternalName service) must neither be
// suppressed nor leak its target past a deny.
func TestNoise_NXDOMAINWithCNAMEChain_NormalPathAndNoLeak(t *testing.T) {
	h := newNoiseHarness(t, "block", clusterDeny, testSearch)
	h.setRR(func(name string) []dns.RR {
		return []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "target.attacker.example.",
		}}
	})

	resp := h.query("registry.gitlab.com.ns.svc.cluster.local")
	if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 {
		t.Fatalf("deny response must not carry the CNAME: %v", resp)
	}

	if len(h.recorded()) != 1 || h.kills.Load() != 1 {
		t.Fatalf("recorded %v kills %d, want the normal deny path", h.recorded(), h.kills.Load())
	}
}

// NODATA is not noise: only NXDOMAIN with no answers is.
func TestNoise_NODATA_IsNotNoise(t *testing.T) {
	h := newNoiseHarness(t, "block", clusterDeny, testSearch)
	h.setAnswer(func(string) (int, bool) { return dns.RcodeSuccess, false }) // NOERROR, no answers

	h.query("registry.gitlab.com.ns.svc.cluster.local")

	if len(h.recorded()) != 1 || h.kills.Load() != 1 {
		t.Fatalf("recorded %v kills %d, want the normal deny path", h.recorded(), h.kills.Load())
	}
}

// AAAA for an existing service in a TLD-named namespace: NODATA from the
// cluster DNS. Must take the normal path (block + deny: rule response,
// event, kill).
func TestNoise_AAAAForExistingServiceInTLDNamedNamespace(t *testing.T) {
	h := newNoiseHarness(t, "block", clusterDeny, testSearch)
	h.setAnswer(func(string) (int, bool) { return dns.RcodeSuccess, false })

	resp := HandleDNSQuery(makeQuery("db.dev.svc.cluster.local", dns.TypeAAAA), h.cfg, h.pol, h.rec, 0, "", "", "", 7)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want the rule's NXDOMAIN", resp.Rcode)
	}

	if len(h.recorded()) != 1 || h.kills.Load() != 1 {
		t.Fatalf("recorded %v kills %d, want event and kill", h.recorded(), h.kills.Load())
	}
}

// Outside the cluster domain (node suffixes, or one injected into a shared
// resolv.conf) nothing is forwarded for classification and the event is
// never suppressed.
func TestNoise_OutsideClusterDomain(t *testing.T) {
	outside := []string{
		"registry.gitlab.com.ec2.internal",
		"registry.gitlab.com.dns.podman",
		"stolen-data.github.com.attacker.com", // poisoned search suffix
	}
	list := append(append([]string{}, testSearch...), "attacker.com")

	t.Run("block: local NXDOMAIN, event, no upstream", func(t *testing.T) {
		h := newNoiseHarness(t, "block", nil, list)

		for _, n := range outside {
			resp := h.query(n)
			if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 {
				t.Fatalf("%s: rcode=%d answers=%d, want local NXDOMAIN", n, resp.Rcode, len(resp.Answer))
			}
		}

		if h.upstream.Load() != 0 {
			t.Fatalf("outside-cluster expansions contacted the upstream %d times", h.upstream.Load())
		}

		if got := h.recorded(); len(got) != 3 {
			t.Fatalf("recorded = %v, want one dns_blocked per query", got)
		}

		_, act := h.rec.Snapshot()
		for _, a := range act {
			if a.Action != actionDNSBlocked || len(a.ResolvedIPs) != 0 {
				t.Fatalf("event %+v, want dns_blocked without sinkhole IPs", a)
			}
		}

		// Nothing is forwarded, so nothing to contain: no CE kill.
		if h.kills.Load() != 0 {
			t.Fatalf("kills = %d, want 0 for outside-cluster expansions", h.kills.Load())
		}
	})

	t.Run("audit: normal path", func(t *testing.T) {
		h := newNoiseHarness(t, "audit", nil, list)
		h.setAnswer(func(string) (int, bool) { return dns.RcodeNameError, false })

		for _, n := range outside {
			h.query(n)
		}

		if h.upstream.Load() != 3 {
			t.Fatalf("audit must forward each once, got %d", h.upstream.Load())
		}

		if got := h.recorded(); len(got) != 3 {
			t.Fatalf("recorded = %v, want 3 dns_observed", got)
		}
	})

	t.Run("deny rule still wins outside the cluster domain", func(t *testing.T) {
		h := newNoiseHarness(t, "block", []policy.Rule{denyFQDN("*.attacker.com", policy.DenyResolutionSinkhole)}, list)
		assertSinkholeA(t, h.query("stolen-data.github.com.attacker.com"))

		if h.kills.Load() != 1 {
			t.Fatalf("deny-rule hit kills = %d, want 1", h.kills.Load())
		}
	})
}

func TestNoise_CustomClusterDomain(t *testing.T) {
	list := []string{"ns.svc.k8s.example"}

	h := newNoiseHarness(t, "block", nil, list)
	h.cfg.ClusterDomain = "k8s.example"
	h.setAnswer(func(string) (int, bool) { return dns.RcodeNameError, false })

	if resp := h.query("registry.gitlab.com.ns.svc.k8s.example"); resp.Rcode != dns.RcodeNameError {
		t.Fatal("custom cluster domain suffix must be classified against the upstream")
	}

	if len(h.recorded()) != 0 || h.upstream.Load() != 1 {
		t.Fatalf("recorded %v upstream %d, want silent noise after one round trip", h.recorded(), h.upstream.Load())
	}

	// With the default cluster domain the same suffix is outside: event, no forward.
	h2 := newNoiseHarness(t, "block", nil, list)
	h2.query("registry.gitlab.com.ns.svc.k8s.example")

	if len(h2.recorded()) != 1 || h2.upstream.Load() != 0 {
		t.Fatalf("recorded %v upstream %d, want event and no forward", h2.recorded(), h2.upstream.Load())
	}
}

// Both splits public-looking, one inside and one outside the cluster domain:
// the stricter class (outside) wins.
func TestClassifyExpansion_MixedSplitsOutsideWins(t *testing.T) {
	t.Parallel()

	got := classifyExpansion("bar.example.com.dev.app", []string{"dev.app", "app"}, "dev.app")
	if got != expOutside {
		t.Fatalf("got %d, want expOutside", got)
	}

	if got = classifyExpansion("bar.example.com.dev.app", []string{"dev.app"}, "dev.app"); got != expCluster {
		t.Fatalf("control: got %d, want expCluster", got)
	}
}

func TestClassifyExpansion(t *testing.T) {
	t.Parallel()

	list := append([]string{}, testSearch...)

	cases := []struct {
		q, domain string
		want      expansionClass
	}{
		{"registry.gitlab.com.ns.svc.cluster.local", "", expCluster},
		{"registry.gitlab.com.cluster.local", "cluster.local", expCluster},
		{"registry.gitlab.com.ec2.internal", "", expOutside},
		{"registry.gitlab.com.ns.svc.cluster.local", "other.local", expOutside},
		{"redis.ns.svc.cluster.local", "", expNone},
		{"registry.gitlab.com", "", expNone},
	}

	tricky := []string{"cluster.local.evil.com", "xcluster.local", "cluster.local", "local"}
	cases = append(cases, struct {
		q, domain string
		want      expansionClass
	}{"registry.gitlab.com.cluster.local.evil.com", "", expOutside},
		struct {
			q, domain string
			want      expansionClass
		}{"registry.gitlab.com.xcluster.local", "", expOutside})

	for _, tc := range cases {
		l := list
		if strings.Contains(tc.q, "evil.com") || strings.Contains(tc.q, "xcluster") {
			l = tricky
		}

		if got := classifyExpansion(tc.q, l, tc.domain); got != tc.want {
			t.Errorf("classifyExpansion(%q, domain %q) = %d, want %d", tc.q, tc.domain, got, tc.want)
		}
	}
}

// The TLD-named namespace fix: db.dev.svc.cluster.local looks public
// (db.dev) but the cluster resolves it, so it is a real name.
func TestNoise_ResolvingTLDNamedNamespaceTakesNormalPath(t *testing.T) {
	resolves := func(name string) (int, bool) {
		if name == "db.dev.svc.cluster.local" {
			return dns.RcodeSuccess, true
		}

		return defaultAnswer(name)
	}

	t.Run("block deny kills immediately", func(t *testing.T) {
		h := newNoiseHarness(t, "block", clusterDeny, testSearch)
		h.setAnswer(resolves)

		resp := h.query("db.dev.svc.cluster.local")
		if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 {
			t.Fatalf("block deny must win over the classification answer: rcode=%d answers=%v", resp.Rcode, resp.Answer)
		}

		if got := h.recorded(); !reflect.DeepEqual(got, []string{"db.dev.svc.cluster.local/dns_denied"}) {
			t.Fatalf("recorded = %v", got)
		}

		if h.kills.Load() != 1 {
			t.Fatalf("kills = %d, want 1 immediate kill", h.kills.Load())
		}
	})

	t.Run("audit forwards once and observes", func(t *testing.T) {
		h := newNoiseHarness(t, "audit", clusterDeny, testSearch)
		h.setAnswer(resolves)

		assertForwardedA(t, h.query("db.dev.svc.cluster.local"))

		if h.upstream.Load() != 1 {
			t.Fatalf("upstream queries = %d, want 1 (response reused)", h.upstream.Load())
		}

		if got := h.recorded(); !reflect.DeepEqual(got, []string{"db.dev.svc.cluster.local/dns_observed"}) {
			t.Fatalf("recorded = %v", got)
		}

		if h.kills.Load() != 0 {
			t.Fatal("audit must not kill")
		}
	})

	t.Run("block no-match keeps the sinkhole", func(t *testing.T) {
		h := newNoiseHarness(t, "block", nil, testSearch)
		h.setAnswer(resolves)

		assertSinkholeA(t, h.query("db.dev.svc.cluster.local"))

		if len(h.recorded()) != 1 || h.kills.Load() != 1 {
			t.Fatalf("recorded %v kills %d", h.recorded(), h.kills.Load())
		}
	})
}

func TestNoise_UpstreamFailureTakesNormalPath(t *testing.T) {
	down := func(h *noiseHarness) {
		h.cfg.Upstreams = nil // hermetic: no fallback resolvers
		h.cfg.DockerUDPDial = func() (*net.UDPConn, error) { return nil, errors.New("down") }
		h.cfg.DockerTCPDial = func() (net.Conn, error) { return nil, errors.New("down") }
	}

	// Block: the name is treated as a real denied name (visibility wins).
	hb := newNoiseHarness(t, "block", clusterDeny, testSearch)
	down(hb)
	hb.query("registry.gitlab.com.ns.svc.cluster.local")

	if len(hb.recorded()) != 1 || hb.kills.Load() != 1 {
		t.Fatalf("block: recorded %v kills %d, want the normal deny path", hb.recorded(), hb.kills.Load())
	}

	// Audit: SERVFAIL as for any failed forward, no event, no kill.
	ha := newNoiseHarness(t, "audit", clusterDeny, testSearch)
	down(ha)

	if resp := ha.query("registry.gitlab.com.ns.svc.cluster.local"); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("audit rcode = %d, want SERVFAIL", resp.Rcode)
	}
}

func TestNoise_UpstreamSERVFAILTakesNormalPath(t *testing.T) {
	h := newNoiseHarness(t, "block", clusterDeny, testSearch)
	h.setAnswer(func(string) (int, bool) { return dns.RcodeServerFailure, false })

	h.query("registry.gitlab.com.ns.svc.cluster.local")

	if len(h.recorded()) != 1 || h.kills.Load() != 1 {
		t.Fatalf("recorded %v kills %d, want the normal deny path", h.recorded(), h.kills.Load())
	}
}

func TestNoise_NotCandidate_KeepsExistingBehaviour(t *testing.T) {
	// Block mode: deny match records, kills, NXDOMAIN per rule. No upstream.
	h := newNoiseHarness(t, "block", clusterDeny, testSearch)

	for _, n := range []string{"redis.ns.svc.cluster.local", "web-0.db.ns.svc.cluster.local", "foo.local.ns.svc.cluster.local"} {
		if resp := h.query(n); resp.Rcode != dns.RcodeNameError {
			t.Fatalf("%s rcode = %d", n, resp.Rcode)
		}
	}

	want := []string{
		"foo.local.ns.svc.cluster.local/dns_denied",
		"redis.ns.svc.cluster.local/dns_denied",
		"web-0.db.ns.svc.cluster.local/dns_denied",
	}
	if got := h.recorded(); !reflect.DeepEqual(got, want) {
		t.Fatalf("recorded = %v, want %v", got, want)
	}

	if h.kills.Load() != 3 || h.upstream.Load() != 0 {
		t.Fatalf("kills = %d upstream = %d, want 3 kills and no upstream contact", h.kills.Load(), h.upstream.Load())
	}

	h2 := newNoiseHarness(t, "block", nil, testSearch)
	assertSinkholeA(t, h2.query("redis.node.dns.podman"))

	h3 := newNoiseHarness(t, "audit", clusterDeny, testSearch)
	h3.setAnswer(func(string) (int, bool) { return dns.RcodeSuccess, true })
	assertForwardedA(t, h3.query("redis.ns.svc.cluster.local"))

	if h3.upstream.Load() != 1 {
		t.Fatalf("audit non-candidate must forward once, got %d", h3.upstream.Load())
	}
}

func TestNoise_KnobOffAndMissingListChangeNothing(t *testing.T) {
	for name, mut := range map[string]func(*noiseHarness){
		"off":        func(h *noiseHarness) { h.cfg.ExpansionSuppression = ExpansionSuppressionOff },
		"nil list":   func(h *noiseHarness) { h.cfg.SearchListFor = func(uint64) []string { return nil } },
		"no func":    func(h *noiseHarness) { h.cfg.SearchListFor = nil },
		"structural": nil, // control: explicit default still suppresses
	} {
		h := newNoiseHarness(t, "block", clusterDeny, testSearch)
		if mut != nil {
			mut(h)
		} else {
			h.cfg.ExpansionSuppression = ExpansionSuppressionStructural
		}

		h.query("registry.gitlab.com.ns.svc.cluster.local")

		suppressed := len(h.recorded()) == 0 && h.kills.Load() == 0
		if wantSuppressed := name == "structural"; suppressed != wantSuppressed {
			t.Errorf("%s: suppressed=%v, want %v (recorded %v, kills %d)", name, suppressed, wantSuppressed, h.recorded(), h.kills.Load())
		}

		if name != "structural" && h.upstream.Load() != 0 {
			t.Errorf("%s: block deny must not contact the upstream", name)
		}
	}
}

func TestNoise_PerContainerList(t *testing.T) {
	lists := map[uint64][]string{1: {"ns.svc.cluster.local"}, 2: {"other.test"}}

	h := newNoiseHarness(t, "block", nil, nil)
	h.cfg.SearchListFor = func(id uint64) []string { return lists[id] }

	q := func(cg uint64, name string) *dns.Msg {
		return HandleDNSQuery(makeQuery(name, dns.TypeA), h.cfg, h.pol, h.rec, 0, "", "", "", cg)
	}

	if r := q(1, "registry.gitlab.com.ns.svc.cluster.local"); r.Rcode != dns.RcodeNameError {
		t.Fatal("container 1 owns the suffix: noise")
	}

	if len(h.recorded()) != 0 {
		t.Fatalf("container 1 produced events: %v", h.recorded())
	}

	// Container 2's list lacks the suffix: not an expansion for it, so the
	// block-mode no-match sinkhole applies and an event is recorded.
	assertSinkholeA(t, q(2, "registry.gitlab.com.ns.svc.cluster.local"))

	if got := h.recorded(); len(got) != 1 {
		t.Fatalf("recorded = %v, want exactly container 2's event", got)
	}
}

func TestNoise_ExplicitAllowRuleWins(t *testing.T) {
	h := newNoiseHarness(t, "block", []policy.Rule{allowFQDN("registry.gitlab.com.ec2.internal", 443)}, testSearch)
	h.setAnswer(func(string) (int, bool) { return dns.RcodeSuccess, true })

	assertForwardedA(t, h.query("registry.gitlab.com.ec2.internal"))

	if h.upstream.Load() != 1 {
		t.Fatalf("allow path must forward exactly once, got %d", h.upstream.Load())
	}
}
