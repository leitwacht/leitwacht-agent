package enforcer

import (
	"bytes"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseResolvConfNdots(t *testing.T) {
	long := "options ndots:" + strings.Repeat("9", 12) + "\n"

	tests := []struct {
		name     string
		in       string
		ndots    int
		explicit bool
	}{
		{"absent", "search a.test\n", 1, false},
		{"empty", "", 1, false},
		{"plain", "options ndots:5\n", 5, true},
		{"zero", "options ndots:0\n", 0, true},
		{"clamp", "options ndots:99\n", 15, true},
		{"clamp huge", long, 15, true},
		{"trailing garbage ignored", "options ndots:3abc\n", 1, false},
		{"last wins", "options ndots:5\noptions ndots:2\n", 2, true},
		{"mixed options", "options timeout:2 ndots:3 attempts:2\n", 3, true},
		{"same line last wins", "options ndots:4 ndots:1\n", 1, true},
		{"invalid ignored", "options ndots:abc\n", 1, false},
		{"negative ignored", "options ndots:-1\n", 1, false},
		{"invalid keeps prior", "options ndots:4\noptions ndots:x\n", 4, true},
		{"comment tail", "options # ndots:7\n", 1, false},
		{"no value", "options ndots:\n", 1, false},
		{"options only", "options\n", 1, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := parseResolvConf([]byte(tc.in))
			if rc.ndots != tc.ndots || rc.ndotsExplicit != tc.explicit {
				t.Fatalf("got ndots=%d explicit=%v, want %d %v", rc.ndots, rc.ndotsExplicit, tc.ndots, tc.explicit)
			}
		})
	}
}

func TestParseResolvConfKeepsSearch(t *testing.T) {
	rc := parseResolvConf([]byte("search A.test. b.test\noptions ndots:5\nnameserver 10.0.0.1\n"))
	if !reflect.DeepEqual(rc.search, []string{"a.test", "b.test"}) || rc.ndots != 5 {
		t.Fatalf("got %+v", rc)
	}
}

func TestParseResolvConfTruncatedNdotsDropped(t *testing.T) {
	data := []byte("search a.test\n" + strings.Repeat("# pad\n", 700) + "options ndots:5")
	if rc := parseResolvConf(data); rc.ndotsExplicit {
		t.Fatalf("ndots from truncated tail accepted: %+v", rc)
	}
}

func TestExtraQueriesTable(t *testing.T) {
	tests := []struct {
		dots, ndots, search, want int
	}{
		{2, 5, 6, 6}, // k8s default: 2-dot name still relative
		{1, 5, 6, 6},
		{2, 2, 6, 0}, // ndots:2 -> absolute first
		{1, 2, 6, 6},
		{2, 1, 6, 0},
		{1, 1, 6, 0},
		{2, 0, 6, 0},
		{2, 5, 0, 0},
		{2, 3, 3, 3},
	}

	for _, tc := range tests {
		if got := extraQueries(tc.dots, tc.ndots, tc.search); got != tc.want {
			t.Errorf("extraQueries(%d,%d,%d)=%d want %d", tc.dots, tc.ndots, tc.search, got, tc.want)
		}
	}
}

func obs(t *testing.T, conf string) DNSConfigObservation {
	t.Helper()

	return observeDNSConfig("c1", parseResolvConf([]byte(conf)), "", true)
}

func TestObserveAndAdvisoryThresholds(t *testing.T) {
	k8s := "search ns.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n"
	tests := []struct {
		name, conf, rec string
		nonCluster      int
	}{
		{"k8s default", k8s, RecLowerNdots, 0},
		{"k8s ndots2", strings.Replace(k8s, "ndots:5", "ndots:2", 1), "", 0},
		{"ndots3 one search", "search cluster.local\noptions ndots:3\n", "", 0},
		{"ndots3 two search", "search svc.cluster.local cluster.local\noptions ndots:3\n", RecLowerNdots, 0},
		{"ndots2 two search", "search svc.cluster.local cluster.local\noptions ndots:2\n", "", 0},
		{"node suffix", "search ns.svc.cluster.local ec2.internal\noptions ndots:2\n", RecNodeSearchDomains, 1},
		{"node suffix default ndots", "search corp.example\n", RecNodeSearchDomains, 1},
		{"both -> node wins", "search ns.svc.cluster.local ec2.internal\noptions ndots:5\n", RecNodeSearchDomains, 1},
		{"no config", "nameserver 1.1.1.1\n", "", 0},
		{"lookalike not cluster", "search evilcluster.local\n", RecNodeSearchDomains, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := obs(t, tc.conf)
			if o.NonClusterSearchCount != tc.nonCluster || o.Recommendation() != tc.rec {
				t.Fatalf("got %+v rec=%q", o, o.Recommendation())
			}

			if (o.Advisory() != nil) != (tc.rec != "") {
				t.Fatalf("advisory presence mismatch")
			}
		})
	}
}

func TestObserveAmplificationValues(t *testing.T) {
	o := obs(t, "search a.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n")
	if o.SearchCount != 3 || o.ExtraQueries2Dot != 3 || o.ExtraQueries1Dot != 3 || !o.NdotsExplicit {
		t.Fatalf("%+v", o)
	}

	o = observeDNSConfig("c", parseResolvConf([]byte("search a.corp.test cluster.local\n")), "corp.test", true)
	if o.NonClusterSearchCount != 1 { // cluster domain is configuration
		t.Fatalf("%+v", o)
	}
}

func TestAdvisoryPayloadSanitisation(t *testing.T) {
	var sb strings.Builder

	sb.WriteString("search ok.example bad<script>.test ")
	sb.WriteString(strings.Repeat("a", 64) + ".test") // label too long
	sb.WriteString(" dup..test a.test b.test c.test d.test\n")

	o := obs(t, sb.String())
	adv := o.Advisory()

	if adv == nil {
		t.Fatal("expected advisory")
	}

	// maxSearchEntries truncates at 6 before sanitising.
	for _, s := range o.NonClusterSuffixes {
		if !validSuffix(s) {
			t.Errorf("unsanitised suffix %q", s)
		}
	}

	if strings.ContainsAny(adv.Message, "<>") || strings.Contains(adv.Message, "script") {
		t.Errorf("message carries unsanitised text: %q", adv.Message)
	}

	if !strings.Contains(adv.Message, "ok.example") || adv.Kind != "dns_config" {
		t.Errorf("message/kind: %q %q", adv.Message, adv.Kind)
	}

	if len(o.NonClusterSuffixes) > maxAdvisorySuffixes {
		t.Errorf("too many suffixes")
	}
}

func TestSanitizeSuffixesCap(t *testing.T) {
	in := []string{"a.t", "b.t", "c.t", "d.t", "e.t", "f.t", "g.t", "h.t"}
	if got := sanitizeSuffixes(in); len(got) != 6 {
		t.Fatalf("got %v", got)
	}
}

func newTestManager(t *testing.T, buf *bytes.Buffer) *Manager {
	t.Helper()

	m := &Manager{logger: slog.New(slog.NewTextHandler(buf, nil))}
	t.Cleanup(m.stopDNSConfigWorker)

	return m
}

func recvObs(t *testing.T, ch chan DNSConfigObservation) (DNSConfigObservation, bool) {
	t.Helper()

	select {
	case o := <-ch:
		return o, true
	case <-time.After(300 * time.Millisecond):
		return DNSConfigObservation{}, false
	}
}

func TestReportDNSConfigLogHygiene(t *testing.T) {
	var buf bytes.Buffer

	m := newTestManager(t, &buf)
	ch := make(chan DNSConfigObservation, 4)
	m.SetOnDNSConfig(func(o DNSConfigObservation) { ch <- o })

	rc := parseResolvConf([]byte("search secret-suffix.corp.test ns.svc.cluster.local\noptions ndots:5\n"))
	info := ContainerInfo{ContainerID: "0123456789abcdef0123", ProjectPath: "g/p", JobID: "7", JobURL: "https://x/7"}
	m.reportDNSConfig(&NetnsContext{}, info, rc, true)

	line := buf.String()
	for _, bad := range []string{"secret-suffix", "corp.test", "cluster.local", "0123456789abcdef0123"} {
		if strings.Contains(line, bad) {
			t.Errorf("log leaks %q: %s", bad, line)
		}
	}

	for _, want := range []string{"dns config observed", "readable=true", "ndots=5", "ndots_explicit=true", "search_count=2",
		"noncluster_search_count=1", "extra_queries_2dot=2", "extra_queries_1dot=2", "container_id=0123456789ab"} {
		if !strings.Contains(line, want) {
			t.Errorf("log missing %q: %s", want, line)
		}
	}

	o, ok := recvObs(t, ch)
	if !ok {
		t.Fatal("callback not invoked")
	}

	a := o.Advisory()
	if a == nil || a.ProjectPath != "g/p" || a.JobID != "7" || a.JobURL != "https://x/7" || a.Details["seen_count"] != 1 {
		t.Fatalf("advisory: %+v", a)
	}

	if strings.HasPrefix(a.Message, "dns config") || !strings.HasPrefix(a.Message, "ndots=5 ") {
		t.Errorf("message shape: %q", a.Message)
	}
}

func TestNoAdviceOnNonK8s(t *testing.T) {
	for _, conf := range []string{
		"search lan\n",
		"search localdomain\n",
		"search corp.example.com\noptions ndots:5\n",
		"search a.test b.test c.test\noptions ndots:5\n",
	} {
		o := observeDNSConfig("c", parseResolvConf([]byte(conf)), "", false)
		if o.K8s || o.Recommendation() != "" || o.Advisory() != nil {
			t.Errorf("%q: advice on non-K8s: %+v", conf, o)
		}
	}

	// A cluster-domain entry or pod shape makes it K8s.
	if o := observeDNSConfig("c", parseResolvConf([]byte("search svc.cluster.local lan\n")), "", false); o.Recommendation() != RecNodeSearchDomains {
		t.Errorf("cluster entry should imply K8s: %+v", o)
	}
}

func TestReportDedupeAndRateLimit(t *testing.T) {
	var buf bytes.Buffer

	m := newTestManager(t, &buf)
	ch := make(chan DNSConfigObservation, 8)
	m.SetOnDNSConfig(func(o DNSConfigObservation) { ch <- o })

	rc := parseResolvConf([]byte("search ns.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n"))
	attr := ContainerInfo{ContainerID: "a", ProjectPath: "g/p"}
	bare := ContainerInfo{ContainerID: "b"}

	// Same netns: unattributed sibling first, a second sibling is skipped,
	// then the attributed build container is DELIVERED despite the hourly
	// limiter (the bare report does not consume its slot).
	n1 := &NetnsContext{}
	m.reportDNSConfig(n1, bare, rc, true)
	m.reportDNSConfig(n1, bare, rc, true)
	m.reportDNSConfig(n1, attr, rc, true)

	if o, ok := recvObs(t, ch); !ok || o.SeenCount != 1 || o.ProjectPath != "" {
		t.Fatalf("first (bare) report: %+v %v", o, ok)
	}

	if o, ok := recvObs(t, ch); !ok || o.ProjectPath != "g/p" || o.SeenCount != 1 {
		t.Fatalf("attributed report after bare: %+v %v", o, ok)
	}

	if _, ok := recvObs(t, ch); ok {
		t.Fatal("unexpected extra report in same netns")
	}

	// A different netns with the same config is rate limited, but counted.
	m.reportDNSConfig(&NetnsContext{}, attr, rc, true)

	if _, ok := recvObs(t, ch); ok {
		t.Fatal("rate limit not applied")
	}

	// After the interval passes the next one reports with seen_count.
	m.dnsCfg.mu.Lock()
	m.dnsCfg.seen[rc.fingerprint()].last = time.Now().Add(-2 * dnsConfigMinInterval)
	m.dnsCfg.mu.Unlock()
	m.reportDNSConfig(&NetnsContext{}, attr, rc, true)

	if o, ok := recvObs(t, ch); !ok || o.SeenCount != 2 {
		t.Fatalf("after interval: %+v %v", o, ok)
	}

	// Different config is independent.
	m.reportDNSConfig(&NetnsContext{}, attr, parseResolvConf([]byte("search svc.cluster.local x.test\n")), true)

	if _, ok := recvObs(t, ch); !ok {
		t.Fatal("different fingerprint should report")
	}
}

func TestAttributedFirstSuppressesLaterBare(t *testing.T) {
	var buf bytes.Buffer

	m := newTestManager(t, &buf)
	ch := make(chan DNSConfigObservation, 4)
	m.SetOnDNSConfig(func(o DNSConfigObservation) { ch <- o })

	rc := parseResolvConf([]byte("search svc.cluster.local cluster.local\noptions ndots:5\n"))
	m.reportDNSConfig(&NetnsContext{}, ContainerInfo{ContainerID: "a", ProjectPath: "g/p"}, rc, true)
	m.reportDNSConfig(&NetnsContext{}, ContainerInfo{ContainerID: "b"}, rc, true)

	if _, ok := recvObs(t, ch); !ok {
		t.Fatal("attributed first should report")
	}

	if _, ok := recvObs(t, ch); ok {
		t.Fatal("later unattributed report should be rate limited")
	}
}

func TestReportNeverBlocksAndDrops(t *testing.T) {
	var buf bytes.Buffer

	m := newTestManager(t, &buf)
	block := make(chan struct{})
	m.SetOnDNSConfig(func(DNSConfigObservation) { <-block })

	done := make(chan struct{})

	go func() {
		defer close(done)

		for i := range dnsConfigQueueLen * 3 {
			rc := parseResolvConf([]byte("search svc.cluster.local d" + strconv.Itoa(i) + ".test\n"))
			m.reportDNSConfig(&NetnsContext{}, ContainerInfo{ContainerID: "c", ProjectPath: "p"}, rc, true)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reportDNSConfig blocked on a stuck callback")
	}

	if m.DNSConfigDropped() == 0 {
		t.Error("expected drops with a full queue")
	}

	close(block)
	m.stopDNSConfigWorker()

	before := m.DNSConfigDropped()
	m.reportDNSConfig(&NetnsContext{}, ContainerInfo{ContainerID: "c", ProjectPath: "p"},
		parseResolvConf([]byte("search svc.cluster.local zz.test\n")), true)

	if m.DNSConfigDropped() != before+1 {
		t.Error("report after shutdown should be dropped")
	}
}

func TestUnreadableLogged(t *testing.T) {
	var buf bytes.Buffer

	m := newTestManager(t, &buf)
	m.reportDNSConfig(&NetnsContext{}, ContainerInfo{ContainerID: "c"}, resolvConf{ndots: defaultNdots}, false)

	if !strings.Contains(buf.String(), "readable=false") {
		t.Errorf("log: %s", buf.String())
	}
}
