package enforcer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// fakeDocker is a UDP+TCP DNS server standing in for Docker's embedded
// resolver; dialUDP/dialTCP match DNSProxyConfig.DockerUDPDial/DockerTCPDial.
type fakeDocker struct {
	dialUDP func() (*net.UDPConn, error)
	dialTCP func() (net.Conn, error)
}

// fakeUpstream serves fn on both UDP and TCP.
func fakeUpstream(t *testing.T, fn func(q *dns.Msg) []*dns.Msg) *fakeDocker {
	t.Helper()

	return fakeDockerSplit(t, fn, fn)
}

func fakeDockerSplit(t *testing.T, udpFn, tcpFn func(q *dns.Msg) []*dns.Msg) *fakeDocker {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			go func() {
				defer c.Close()

				co := &dns.Conn{Conn: c}

				q, readErr := co.ReadMsg()
				if readErr != nil {
					return
				}

				for _, r := range tcpFn(q) {
					_ = co.WriteMsg(r)
				}
			}()
		}
	}()

	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	t.Cleanup(func() { _ = srv.Close() })

	go func() {
		buf := make([]byte, 4096)

		for {
			n, from, readErr := srv.ReadFromUDP(buf)
			if readErr != nil {
				return
			}

			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}

			for _, r := range udpFn(q) {
				if packed, packErr := r.Pack(); packErr == nil {
					_, _ = srv.WriteToUDP(packed, from)
				}
			}
		}
	}()

	return &fakeDocker{
		dialUDP: func() (*net.UDPConn, error) {
			return net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
		},
		dialTCP: func() (net.Conn, error) { return net.Dial("tcp4", ln.Addr().String()) },
	}
}

func aRR(name, ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip).To4(),
	}
}

func cnameRR(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: dns.Fqdn(target),
	}
}

func replyTo(q *dns.Msg, id uint16, rrs ...dns.RR) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Id = id
	r.Answer = rrs

	return r
}

func TestExchangeViaDocker_RandomIDAndRestore(t *testing.T) {
	var seen atomic.Uint32

	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		seen.Store(uint32(q.Id))

		return []*dns.Msg{replyTo(q, q.Id, aRR("a.example.com", "198.51.100.4"))}
	})

	// Over many queries the upstream ID must not simply equal the client's.
	differed := false

	for range 20 {
		msg := makeQuery("a.example.com", dns.TypeA)
		msg.Id = 4242

		resp, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, msg)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}

		if resp.Id != 4242 {
			t.Fatalf("client id not restored: got %d", resp.Id)
		}

		if seen.Load() != 4242 {
			differed = true
		}
	}

	if !differed {
		t.Fatal("upstream query reused the client's DNS ID")
	}
}

func TestExchangeViaDocker_UDPSkipsForgedWrongID(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		return []*dns.Msg{
			replyTo(q, q.Id+1, aRR("a.example.com", "203.0.113.66")), // forged: wrong ID
			replyTo(q, q.Id, aRR("a.example.com", "198.51.100.4")),
		}
	})

	resp, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, makeQuery("a.example.com", dns.TypeA))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "198.51.100.4" {
		t.Fatalf("accepted forged reply: %v", resp.Answer)
	}
}

func TestExchangeDockerTCP_WrongIDRejected(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		return []*dns.Msg{replyTo(q, q.Id+1, aRR("a.example.com", "203.0.113.66"))}
	})

	if _, err := exchangeDockerTCP(conn.dialTCP, makeQuery("a.example.com", dns.TypeA)); err == nil {
		t.Fatal("reply with a wrong ID was accepted")
	}
}

func TestExchangeViaDocker_TruncatedRetriesOverTCP(t *testing.T) {
	var tcpHits atomic.Int32

	conn := fakeDockerSplit(t,
		func(q *dns.Msg) []*dns.Msg {
			r := replyTo(q, q.Id)
			r.Truncated = true

			return []*dns.Msg{r}
		},
		func(q *dns.Msg) []*dns.Msg {
			tcpHits.Add(1)

			return []*dns.Msg{replyTo(q, q.Id, aRR("a.example.com", "198.51.100.4"))}
		})

	resp, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, makeQuery("a.example.com", dns.TypeA))
	if err != nil || resp.Truncated || len(resp.Answer) != 1 || tcpHits.Load() != 1 {
		t.Fatalf("err=%v truncated=%v answers=%d tcp=%d", err, resp != nil && resp.Truncated, len(resp.Answer), tcpHits.Load())
	}
}

func TestExchangeViaDocker_UDPUsedFirstNoTCPWhenNotTruncated(t *testing.T) {
	var tcpHits atomic.Int32

	conn := fakeDockerSplit(t,
		func(q *dns.Msg) []*dns.Msg { return []*dns.Msg{replyTo(q, q.Id, aRR("a.example.com", "198.51.100.4"))} },
		func(q *dns.Msg) []*dns.Msg { tcpHits.Add(1); return nil })

	if _, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, makeQuery("a.example.com", dns.TypeA)); err != nil {
		t.Fatal(err)
	}

	if tcpHits.Load() != 0 {
		t.Fatal("TCP used although the UDP reply was complete")
	}
}

func TestForwardQuery_SingleLabelDockerFailureServfails(t *testing.T) {
	cfg, _, _ := testDNSConfig(policy.ActionAudit, nil)
	cfg.Upstreams = []string{"127.0.0.1:1"}                                             // would be tried if we fell through
	cfg.DockerUDPDial = func() (*net.UDPConn, error) { return nil, errors.New("down") } //nolint:err113 // test

	if _, err := forwardQuery(makeQuery("db", dns.TypeA), cfg); err == nil {
		t.Fatal("expected failure for single-label name")
	}
}

func TestExchangeViaDocker_LargeAnswerOverTCP(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		var rrs []dns.RR
		for i := range 100 {
			rrs = append(rrs, aRR("a.example.com", net.IPv4(198, 51, 100, byte(i)).String()))
		}

		return []*dns.Msg{replyTo(q, q.Id, rrs...)}
	})

	resp, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, makeQuery("a.example.com", dns.TypeA))
	if err != nil || len(resp.Answer) != 100 {
		t.Fatalf("large answer: err=%v n=%d", err, len(resp.Answer))
	}
}

func TestExchangeViaDocker_QuestionMismatchRejected(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		r := replyTo(q, q.Id, aRR("other.example.net", "203.0.113.66"))
		r.Question = []dns.Question{{Name: "other.example.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}

		return []*dns.Msg{r}
	})

	_, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, makeQuery("a.example.com", dns.TypeA))
	if err == nil {
		t.Fatal("reply for a different question was accepted")
	}
}

func TestExchangeViaDocker_QuestionCaseInsensitive(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		r := replyTo(q, q.Id, aRR("a.example.com", "198.51.100.4"))
		r.Question[0].Name = "A.EXAMPLE.COM."

		return []*dns.Msg{r}
	})

	_, err := exchangeViaDocker(conn.dialUDP, conn.dialTCP, makeQuery("a.example.com", dns.TypeA))
	if err != nil {
		t.Fatalf("case-different question rejected: %v", err)
	}
}

// dockerCfg returns a block-mode config forwarding via a fake Docker
// upstream, capturing allow-map seeds.
func dockerCfg(t *testing.T, dock *fakeDocker) (*DNSProxyConfig, *policy.ResolvedPolicy, *[]string) {
	t.Helper()

	cfg, pol, _ := testDNSConfig(policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)})
	cfg.Upstreams = nil
	cfg.DockerUDPDial = dock.dialUDP
	cfg.DockerTCPDial = dock.dialTCP

	var seeded []string

	cfg.AddToAllowMap = func(ip net.IP, _ []int, _ uint32) error {
		seeded = append(seeded, ip.String())

		return nil
	}

	return cfg, pol, &seeded
}

func TestHandleDNSQuery_OutOfChainARecordNotSeeded(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		return []*dns.Msg{replyTo(q, q.Id,
			aRR("a.example.com", "198.51.100.4"),
			aRR("evil.example.net", "203.0.113.66"), // not the qname, not in a CNAME chain
		)}
	})

	cfg, pol, seeded := dockerCfg(t, conn)

	resp := HandleDNSQuery(makeQuery("a.example.com", dns.TypeA), cfg, pol, nil, 0, "", "", "", 1)

	if len(*seeded) != 1 || (*seeded)[0] != "198.51.100.4" {
		t.Fatalf("seeded = %v, want only 198.51.100.4", *seeded)
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "203.0.113.66" {
			t.Fatal("out-of-chain A record was returned to the client")
		}
	}
}

func TestHandleDNSQuery_CNAMEChainSeeded(t *testing.T) {
	conn := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		// Records deliberately out of order.
		return []*dns.Msg{replyTo(q, q.Id,
			aRR("edge.cdn.example.org", "198.51.100.9"),
			cnameRR("mid.cdn.example.org", "edge.cdn.example.org"),
			cnameRR("a.example.com", "mid.cdn.example.org"),
			aRR("unrelated.example.org", "203.0.113.66"),
		)}
	})

	cfg, pol, seeded := dockerCfg(t, conn)

	_ = HandleDNSQuery(makeQuery("A.Example.com", dns.TypeA), cfg, pol, nil, 0, "", "", "", 1)

	if len(*seeded) != 1 || (*seeded)[0] != "198.51.100.9" {
		t.Fatalf("seeded = %v, want only 198.51.100.9", *seeded)
	}
}

func TestDNSProxy_ShedsWhenSaturated(t *testing.T) {
	cfg, pol, _ := testDNSConfig(policy.ActionBlock, nil)
	p := NewDNSProxy(cfg)
	_ = pol

	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	p.Start(udp, tcp)
	defer p.Stop()

	for range cap(p.sem) {
		p.sem <- struct{}{}
	}

	c := &dns.Client{Timeout: 2 * time.Second}

	resp, _, err := c.Exchange(makeQuery("a.example.com", dns.TypeA), udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL when saturated", resp.Rcode)
	}

	// Free the slots: normal service resumes (blocked -> sinkhole A).
	for range cap(p.sem) {
		<-p.sem
	}

	resp, _, err = c.Exchange(makeQuery("a.example.com", dns.TypeA), udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.Rcode == dns.RcodeServerFailure {
		t.Fatal("still shedding after slots freed")
	}
}

func TestRecordDNS_ResolvedIPsCappedAndDeduped(t *testing.T) {
	r := NewViolationRecorder(nil)

	for i := range 200 {
		ip := net.IPv4(198, 51, byte(i/256), byte(i%256)).String()
		r.RecordDNS("big.example.com", "A", "dns_allowed", []string{ip, ip}, 0, "", "", "")
	}

	_, activity, _ := r.SnapshotAndReset()
	if len(activity) != 1 {
		t.Fatalf("entries = %d", len(activity))
	}

	e := activity[0]
	if len(e.ResolvedIPs) != maxResolvedIPsPerEntry {
		t.Fatalf("ResolvedIPs = %d, want %d", len(e.ResolvedIPs), maxResolvedIPsPerEntry)
	}

	if e.ResolvedIPsDropped == 0 {
		t.Fatal("expected ResolvedIPsDropped > 0")
	}
}

func TestRecordDNS_EnforcementHeadroomAndOverflow(t *testing.T) {
	r := NewViolationRecorder(nil)

	// Flood with allowed names well past the cap.
	for i := range maxDNSEntriesPerContainer + 500 {
		r.RecordDNS("a"+itoa(i)+".example.com", "A", "dns_allowed", nil, 0, "", "", "")
	}

	// Blocked names must still be recorded in the reserved headroom.
	for i := range 50 {
		r.RecordDNS("b"+itoa(i)+".evil.com", "A", "dns_blocked", []string{SinkholeIPv4}, 0, "", "", "")
	}

	_, activity, overflow := r.SnapshotAndReset()

	blocked := 0

	for _, e := range activity {
		if e.Action == "dns_blocked" {
			blocked++
		}
	}

	if blocked != 50 {
		t.Fatalf("blocked entries kept = %d, want 50", blocked)
	}

	if overflow <= 0 {
		t.Fatal("expected a positive overflow count for dropped DNS entries")
	}

	if len(activity) > maxDNSEntriesPerContainer {
		t.Fatalf("entries = %d exceeds cap", len(activity))
	}
}

func itoa(i int) string {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i)).String()
}

func TestDNSCache_SkipsSinkholeIP(t *testing.T) {
	c := NewDNSCache()
	c.Record("blocked.example.com", []string{SinkholeIPv4, "198.51.100.4"})

	if got := c.Lookup(SinkholeIPv4); got != "" {
		t.Fatalf("sinkhole IP cached as %q", got)
	}

	if got := c.Lookup("198.51.100.4"); got != "blocked.example.com" {
		t.Fatalf("real IP not cached: %q", got)
	}
}

// TestManager_DNSViolationWiredAndDeduped drives the violation hook the
// manager installs on a real attached netns context: it must resolve the
// container, run the callback asynchronously, and only once per container.
func TestManager_DNSViolationWiredAndDeduped(t *testing.T) {
	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	defer mgr.DetachAll()

	type call struct {
		containerID string
		domain      string
	}

	calls := make(chan call, 8)

	mgr.SetOnDNSViolation(func(containerID, domain, _ string) error {
		calls <- call{containerID, domain}

		return nil
	})

	const cid = "abcdef123456"

	e, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: cid, ProjectPath: "p/x"}, 1234, testPolicy("block"))
	if err != nil || e == nil {
		t.Fatalf("attach: %v", err)
	}

	mgr.mu.Lock()
	var nctx *NetnsContext
	for _, n := range mgr.netnsContexts {
		nctx = n
	}
	mgr.mu.Unlock()

	hook := nctx.dnsProxy.cfg.OnDNSViolation
	if hook == nil {
		t.Fatal("OnDNSViolation not wired into the DNS proxy config")
	}

	// Attributed by cgroup ID.
	hook(e.cgroupID, "evil.example.com", "dns_blocked")
	// Duplicates are suppressed.
	hook(e.cgroupID, "evil2.example.com", "dns_blocked")

	select {
	case c := <-calls:
		if c.domain != "evil.example.com" || c.containerID != cid {
			t.Fatalf("call = %+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback not invoked")
	}

	select {
	case c := <-calls:
		t.Fatalf("callback fired more than once per container: %+v", c)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestManager_DNSViolationUnresolvedNoAction: with a single container in the
// netns, neither a missing (0) nor an unknown non-zero cgroup may fall back
// to "the only container".
func TestManager_DNSViolationUnresolvedNoAction(t *testing.T) {
	mgr, e, hook := attachedBlockManager(t)

	calls := make(chan string, 4)

	mgr.SetOnDNSViolation(func(containerID, _, _ string) error {
		calls <- containerID

		return nil
	})

	hook(0, "evil.example.com", "dns_blocked")
	hook(e.cgroupID+1000, "evil.example.com", "dns_blocked")

	select {
	case id := <-calls:
		t.Fatalf("callback fired for unresolved cgroup (container %q)", id)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestManager_DNSViolationRetriesAfterFailure: a failed handler may be
// retried by a later violation, but only a bounded number of times.
func TestManager_DNSViolationRetriesAfterFailure(t *testing.T) {
	mgr, e, hook := attachedBlockManager(t)

	var n atomic.Int32

	mgr.SetOnDNSViolation(func(_, _, _ string) error {
		n.Add(1)

		return errors.New("kill failed") //nolint:err113 // test
	})

	for range 10 {
		hook(e.cgroupID, "evil.example.com", "dns_blocked")
		time.Sleep(50 * time.Millisecond)
	}

	if got := n.Load(); got != maxDNSViolationAttempts {
		t.Fatalf("handler ran %d times, want %d", got, maxDNSViolationAttempts)
	}
}

func attachedBlockManager(t *testing.T) (*Manager, *Enforcer, func(uint64, string, string)) {
	t.Helper()

	fp := &fakePlatform{cgroupPath: "/sys/fs/cgroup/test"}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	t.Cleanup(func() { mgr.DetachAll() })

	e, err := mgr.Attach(context.Background(), ContainerInfo{ContainerID: "abcdef123456", ProjectPath: "p/x"}, 1234, testPolicy("block"))
	if err != nil || e == nil {
		t.Fatalf("attach: %v", err)
	}

	mgr.mu.Lock()
	var nctx *NetnsContext
	for _, n := range mgr.netnsContexts {
		nctx = n
	}
	mgr.mu.Unlock()

	return mgr, e, nctx.dnsProxy.cfg.OnDNSViolation
}

// TestManager_DNSViolationOnlyKillsBlockModeContainer: in a shared netns the
// proxy runs the strictest member policy, so a violation attributed to an
// audit sibling must not invoke the (kill) callback; one attributed to the
// block-mode container must.
func TestManager_DNSViolationOnlyKillsBlockModeContainer(t *testing.T) {
	fp := &fakePlatform{
		cgroupPath: "/sys/fs/cgroup/test",
		netnsByPID: map[int]uint64{100: 7777, 101: 7777},
	}
	mgr := NewManager(testLogger(), 32, []string{"1.1.1.1:53"}, nil, fp, CredwatchConfig{}, ProcMemConfig{})
	mgr.NetnsGrace = 0

	t.Cleanup(func() { mgr.DetachAll() })

	calls := make(chan string, 4)

	mgr.SetOnDNSViolation(func(containerID, _, _ string) error {
		calls <- containerID

		return nil
	})

	ctx := context.Background()
	const auditID, blockID = "audit0000000000", "block0000000000"

	auditE, err := mgr.Attach(ctx, ContainerInfo{ContainerID: auditID, ProjectPath: "p/x"}, 100, testPolicy("audit"))
	if err != nil || auditE == nil {
		t.Fatalf("attach audit: %v", err)
	}

	blockE, err := mgr.Attach(ctx, ContainerInfo{ContainerID: blockID, ProjectPath: "p/x"}, 101, testPolicy("block"))
	if err != nil || blockE == nil {
		t.Fatalf("attach block: %v", err)
	}

	hook := auditE.ctx.dnsProxy.cfg.OnDNSViolation

	hook(auditE.cgroupID, "evil.example.com", "dns_blocked")

	select {
	case id := <-calls:
		t.Fatalf("callback fired for audit-mode container %q", id)
	case <-time.After(200 * time.Millisecond):
	}

	hook(blockE.cgroupID, "evil.example.com", "dns_blocked")

	select {
	case id := <-calls:
		if id != blockID {
			t.Fatalf("callback container = %q, want %q", id, blockID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback not invoked for block-mode container")
	}
}
