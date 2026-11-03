package enforcer

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// cacheHarness wires a cache-enabled config to a counting, programmable
// in-process upstream. No network is involved.
type cacheHarness struct {
	cfg      *DNSProxyConfig
	pol      *policy.ResolvedPolicy
	rec      *ViolationRecorder
	upstream atomic.Int64
	seeded   atomic.Int64
	clock    atomic.Int64 // offset in seconds added to the cache clock

	mu     sync.Mutex
	ttl    uint32
	rcode  int
	answer bool
}

func newCacheHarness(t *testing.T, action string, rules []policy.Rule, size int) *cacheHarness {
	t.Helper()

	cfg, pol, rec := testDNSConfig(action, rules)
	h := &cacheHarness{cfg: cfg, pol: pol, rec: rec, ttl: 60, answer: true}

	up := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
		h.upstream.Add(1)

		h.mu.Lock()
		ttl, rcode, withA := h.ttl, h.rcode, h.answer
		h.mu.Unlock()

		r := replyTo(q, q.Id)
		r.Rcode = rcode

		if withA {
			rr := aRR(strings.TrimSuffix(q.Question[0].Name, "."), fakeUpstreamIP)
			rr.Header().Ttl = ttl
			r.Answer = []dns.RR{rr}
		}

		return []*dns.Msg{r}
	})
	cfg.Upstreams = nil
	cfg.DockerUDPDial = up.dialUDP
	cfg.DockerTCPDial = up.dialTCP
	cfg.AddToAllowMap = func(net.IP, []int, uint32) error {
		h.seeded.Add(1)

		return nil
	}

	cfg.cache = newDNSCache(size)
	if cfg.cache != nil {
		base := time.Now()
		cfg.cache.now = func() time.Time { return base.Add(time.Duration(h.clock.Load()) * time.Second) }
	}

	return h
}

func (h *cacheHarness) set(ttl uint32, rcode int, withAnswer bool) {
	h.mu.Lock()
	h.ttl, h.rcode, h.answer = ttl, rcode, withAnswer
	h.mu.Unlock()
}

func (h *cacheHarness) query(name string, qtype uint16) *dns.Msg {
	return HandleDNSQuery(makeQuery(name, qtype), h.cfg, h.pol, h.rec, 0, "", "", "", 7)
}

func (h *cacheHarness) entries() int { return h.cfg.cache.stats().Entries }

func TestDNSCache_HitMissAndSideEffects(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)

	first := h.query("a.example.com", dns.TypeA)
	assertForwardedA(t, first)

	// Mixed case + a fresh ID: same cache key, client ID/question echoed.
	q := makeQuery("A.Example.COM", dns.TypeA)
	q.Id = 31337

	second := HandleDNSQuery(q, h.cfg, h.pol, h.rec, 0, "", "", "", 7)
	assertForwardedA(t, second)

	if second.Id != 31337 || second.Question[0].Name != "A.Example.COM." {
		t.Fatalf("hit did not echo client id/question: id=%d q=%v", second.Id, second.Question)
	}

	if got := h.upstream.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1 (second must be a hit)", got)
	}

	if st := h.cfg.cache.stats(); st.Hits != 1 || st.Misses != 1 || st.Entries != 1 {
		t.Fatalf("stats = %+v, want 1 hit / 1 miss / 1 entry", st)
	}

	// Side effects preserved on the hit: allow map re-seeded, event recorded.
	if got := h.seeded.Load(); got != 2 {
		t.Fatalf("allow-map seeds = %d, want 2 (one per query)", got)
	}

	_, act := h.rec.Snapshot()
	if len(act) != 1 || act[0].QueryCount != 2 || act[0].Action != "dns_allowed" ||
		len(act[0].ResolvedIPs) != 1 || act[0].ResolvedIPs[0] != fakeUpstreamIP {
		t.Fatalf("dns activity = %+v, want one dns_allowed entry, count 2, resolved %s", act, fakeUpstreamIP)
	}
}

func TestDNSCache_TTLDecrementAndExpiry(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)
	h.set(60, dns.RcodeSuccess, true)

	h.query("a.example.com", dns.TypeA)

	h.clock.Store(25)

	resp := h.query("a.example.com", dns.TypeA)
	if ttl := resp.Answer[0].Header().Ttl; ttl != 35 {
		t.Fatalf("TTL after 25s = %d, want 35", ttl)
	}

	if h.upstream.Load() != 1 {
		t.Fatalf("expected a hit at 25s, upstream = %d", h.upstream.Load())
	}

	// Last second still served, with TTL 1.
	h.clock.Store(59)

	if ttl := h.query("a.example.com", dns.TypeA).Answer[0].Header().Ttl; ttl != 1 {
		t.Fatalf("TTL at 59s = %d, want 1", ttl)
	}

	// Exactly at expiry: miss, refetched.
	h.clock.Store(60)
	h.query("a.example.com", dns.TypeA)

	if h.upstream.Load() != 2 {
		t.Fatalf("expected refetch at expiry, upstream = %d", h.upstream.Load())
	}
}

func TestDNSCache_TTLCapAndZero(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("*.example.com", 443)}, 8)

	h.set(86400, dns.RcodeSuccess, true) // capTTL -> 300
	h.query("big.example.com", dns.TypeA)

	h.clock.Store(299)
	h.query("big.example.com", dns.TypeA)

	if h.upstream.Load() != 1 {
		t.Fatalf("expected hit at 299s, upstream = %d", h.upstream.Load())
	}

	h.clock.Store(300)
	h.query("big.example.com", dns.TypeA)

	if h.upstream.Load() != 2 {
		t.Fatalf("expected expiry at the 300s hard cap, upstream = %d", h.upstream.Load())
	}

	h.set(0, dns.RcodeSuccess, true) // TTL 0 is never cached
	h.query("zero.example.com", dns.TypeA)
	h.query("zero.example.com", dns.TypeA)

	if h.upstream.Load() != 4 {
		t.Fatalf("TTL-0 answer was cached, upstream = %d", h.upstream.Load())
	}
}

func TestDNSCache_AuditForwardingIsCached(t *testing.T) {
	h := newCacheHarness(t, policy.ActionAudit, nil, 8)

	h.query("anything.example.net", dns.TypeA)
	h.query("anything.example.net", dns.TypeA)

	if h.upstream.Load() != 1 || h.entries() != 1 {
		t.Fatalf("audit no-match forward: upstream=%d entries=%d, want 1/1", h.upstream.Load(), h.entries())
	}

	_, act := h.rec.Snapshot()
	if len(act) != 1 || act[0].Action != "dns_observed" || act[0].QueryCount != 2 {
		t.Fatalf("activity = %+v, want dns_observed x2", act)
	}
}

func TestDNSCache_NeverCachesIneligible(t *testing.T) {
	t.Run("upstream NXDOMAIN", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)
		h.set(60, dns.RcodeNameError, false)

		h.query("a.example.com", dns.TypeA)
		h.query("a.example.com", dns.TypeA)

		if h.entries() != 0 || h.upstream.Load() != 2 {
			t.Fatalf("NXDOMAIN cached: entries=%d upstream=%d", h.entries(), h.upstream.Load())
		}
	})

	t.Run("upstream NOERROR no answer", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)
		h.set(60, dns.RcodeSuccess, false)

		h.query("a.example.com", dns.TypeA)

		if h.entries() != 0 {
			t.Fatalf("empty NOERROR cached: entries=%d", h.entries())
		}
	})

	t.Run("upstream SERVFAIL", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)
		h.set(60, dns.RcodeServerFailure, false)

		h.query("a.example.com", dns.TypeA)

		if h.entries() != 0 {
			t.Fatalf("SERVFAIL cached: entries=%d", h.entries())
		}
	})

	t.Run("all upstreams down (synthesized SERVFAIL)", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)
		h.cfg.DockerUDPDial = func() (*net.UDPConn, error) { return nil, net.ErrClosed }
		h.cfg.Upstreams = nil

		resp := h.query("a.example.com", dns.TypeA)
		if resp.Rcode != dns.RcodeServerFailure || h.entries() != 0 {
			t.Fatalf("rcode=%d entries=%d, want SERVFAIL and nothing cached", resp.Rcode, h.entries())
		}
	})

	t.Run("AAAA stripped to empty", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)

		up := fakeUpstream(t, func(q *dns.Msg) []*dns.Msg {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("2001:db8::1"),
			}

			return []*dns.Msg{replyTo(q, q.Id, rr)}
		})
		h.cfg.DockerUDPDial, h.cfg.DockerTCPDial = up.dialUDP, up.dialTCP

		resp := h.query("a.example.com", dns.TypeAAAA)
		if len(resp.Answer) != 0 || h.entries() != 0 {
			t.Fatalf("answers=%d entries=%d, want none", len(resp.Answer), h.entries())
		}
	})

	t.Run("deny rule (sinkhole and nxdomain)", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{
			denyFQDN("bad.example.com", ""),
			denyFQDN("gone.example.com", policy.DenyResolutionNXDomain),
		}, 8)

		h.query("bad.example.com", dns.TypeA)
		h.query("gone.example.com", dns.TypeA)

		if h.entries() != 0 || h.upstream.Load() != 0 {
			t.Fatalf("deny cached or forwarded: entries=%d upstream=%d", h.entries(), h.upstream.Load())
		}
	})

	t.Run("block-mode no match", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)

		assertSinkholeA(t, h.query("other.example.net", dns.TypeA))
		assertSinkholeA(t, h.query("other.example.net", dns.TypeA))

		if h.entries() != 0 || h.upstream.Load() != 0 {
			t.Fatalf("no-match cached or forwarded: entries=%d upstream=%d", h.entries(), h.upstream.Load())
		}
	})

	t.Run("reserved attach name", func(t *testing.T) {
		h := newCacheHarness(t, policy.ActionAudit, nil, 8)

		h.query(ReservedDomains[0], dns.TypeA)

		if h.entries() != 0 {
			t.Fatalf("synthesized attach reply cached: entries=%d", h.entries())
		}
	})

	t.Run("truncated", func(t *testing.T) {
		resp := replyTo(makeQuery("a.example.com", dns.TypeA), 1, aRR("a.example.com", fakeUpstreamIP))
		resp.Truncated = true

		if cacheableTTL(resp) != 0 {
			t.Fatal("truncated response must not be cacheable")
		}
	})
}

func TestDNSCache_ExpansionClassificationNotCached(t *testing.T) {
	h := newNoiseHarness(t, policy.ActionAudit, nil, testSearch)
	h.answerMu.Lock()
	h.answer = func(string) (int, bool) { return dns.RcodeSuccess, true }
	h.answerMu.Unlock()
	h.cfg.cache = newDNSCache(8)

	// github.com is a public-looking base under the cluster domain: the
	// classification probe answers, and the reused answer is not cached.
	h.query("github.com.svc.cluster.local")
	h.query("github.com.svc.cluster.local")

	if st := h.cfg.cache.stats(); st.Entries != 0 || h.upstream.Load() != 2 {
		t.Fatalf("expansion answer cached: entries=%d upstream=%d", st.Entries, h.upstream.Load())
	}
}

func TestDNSCache_PolicyUpdateAndStopFlush(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 8)
	h.cfg.CacheSize = 8

	p := NewDNSProxy(h.cfg) // replaces h.cfg.cache with a real-clock cache
	h.cfg.cache.now = func() time.Time { return time.Now().Add(time.Duration(h.clock.Load()) * time.Second) }

	h.query("a.example.com", dns.TypeA)

	if p.CacheStats().Entries != 1 {
		t.Fatalf("entries = %d, want 1", p.CacheStats().Entries)
	}

	p.UpdatePolicy(h.pol) // identical policy content: cache kept

	if p.CacheStats().Entries != 1 {
		t.Fatal("UpdatePolicy with an unchanged policy flushed the cache")
	}

	changed := *h.pol
	changed.RuleSets = map[string][]policy.Rule{"": {allowFQDN("a.example.com", 443), allowFQDN("b.example.com", 443)}}
	h.pol = &changed
	p.UpdatePolicy(h.pol)

	if p.CacheStats().Entries != 0 {
		t.Fatal("UpdatePolicy with a changed policy did not flush the cache")
	}

	h.query("a.example.com", dns.TypeA)
	h.query("a.example.com", dns.TypeA)

	if h.upstream.Load() != 2 {
		t.Fatalf("upstream = %d, want 2 (refetch after flush, then hit)", h.upstream.Load())
	}

	p.Stop()

	if p.CacheStats().Entries != 0 {
		t.Fatal("Stop did not flush the cache")
	}
}

func TestDNSCache_FlushDiscardsInFlightStore(t *testing.T) {
	c := newDNSCache(4)
	q := makeQuery("a.example.com", dns.TypeA)
	key, _ := dnsCacheKeyFor(q)
	gen := c.generation()

	c.flush() // policy change while the upstream query is in flight
	c.put(key, replyTo(q, q.Id, aRR("a.example.com", fakeUpstreamIP)), []string{fakeUpstreamIP}, gen)

	if c.stats().Entries != 0 {
		t.Fatal("a store that began before a flush must be discarded")
	}
}

func TestDNSCache_LRUBound(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("*.example.com", 443)}, 3)

	for i := range 3 {
		h.query(fmt.Sprintf("h%d.example.com", i), dns.TypeA)
	}

	h.query("h0.example.com", dns.TypeA) // touch h0: h1 is now the LRU victim
	h.query("h3.example.com", dns.TypeA) // evicts h1

	if h.entries() != 3 {
		t.Fatalf("entries = %d, want bound 3", h.entries())
	}

	before := h.upstream.Load()

	h.query("h0.example.com", dns.TypeA) // still cached
	h.query("h1.example.com", dns.TypeA) // evicted -> refetch

	if got := h.upstream.Load() - before; got != 1 {
		t.Fatalf("upstream queries after eviction = %d, want 1 (only h1)", got)
	}
}

func TestDNSCache_Disabled(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("a.example.com", 443)}, 0)

	if h.cfg.cache != nil {
		t.Fatal("size 0 must disable the cache")
	}

	h.query("a.example.com", dns.TypeA)
	h.query("a.example.com", dns.TypeA)

	if h.upstream.Load() != 2 {
		t.Fatalf("upstream = %d, want 2 with cache disabled", h.upstream.Load())
	}

	p := NewDNSProxy(h.cfg)
	p.UpdatePolicy(h.pol) // nil-safe flush
	p.Stop()

	if st := p.CacheStats(); st != (DNSCacheStats{}) {
		t.Fatalf("stats = %+v, want zero", st)
	}
}

func TestDNSCache_DOBitSeparatesEntries(t *testing.T) {
	plain := makeQuery("a.example.com", dns.TypeA)
	signed := makeQuery("a.example.com", dns.TypeA)
	signed.SetEdns0(1232, true)

	k1, _ := dnsCacheKeyFor(plain)
	k2, _ := dnsCacheKeyFor(signed)

	if k1 == k2 {
		t.Fatal("DO and non-DO queries must not share a cache entry")
	}

	cd := makeQuery("a.example.com", dns.TypeA)
	cd.CheckingDisabled = true

	if k3, _ := dnsCacheKeyFor(cd); k3 == k1 {
		t.Fatal("CD and non-CD queries must not share a cache entry")
	}
}

func TestDNSCache_NonQueryOpcodeBypasses(t *testing.T) {
	q := makeQuery("a.example.com", dns.TypeA)
	q.Opcode = dns.OpcodeNotify

	if _, ok := dnsCacheKeyFor(q); ok {
		t.Fatal("non-QUERY opcode must bypass the cache")
	}
}

func TestDNSCache_OversizedResponseNotCached(t *testing.T) {
	c := newDNSCache(4)
	q := makeQuery("a.example.com", dns.TypeA)
	key, _ := dnsCacheKeyFor(q)

	small := replyTo(q, q.Id, aRR("a.example.com", fakeUpstreamIP))
	c.put(key, small, nil, c.generation())

	if c.stats().Entries != 1 {
		t.Fatal("small response should be cached")
	}

	c.flush()

	big := replyTo(q, q.Id, aRR("a.example.com", fakeUpstreamIP))
	for i := range 40 {
		big.Answer = append(big.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", 100) + fmt.Sprint(i)},
		})
	}

	if big.Len() <= maxCachedResponseSize {
		t.Fatalf("test response too small: %d", big.Len())
	}

	c.put(key, big, nil, c.generation())

	if c.stats().Entries != 0 {
		t.Fatal("oversized response must not be cached")
	}
}

func TestDNSCache_EDNSOptHandling(t *testing.T) {
	c := newDNSCache(4)

	// First client: EDNS with a cookie; upstream reply carries an OPT with a cookie.
	q1 := makeQuery("a.example.com", dns.TypeA)
	q1.SetEdns0(1232, false)

	key, _ := dnsCacheKeyFor(q1)
	up := replyTo(q1, q1.Id, aRR("a.example.com", fakeUpstreamIP))
	up.SetEdns0(4096, false)
	up.IsEdns0().Option = append(up.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "aabbccddeeff00112233445566778899"})
	c.put(key, up, nil, c.generation())

	// Non-EDNS client: no OPT at all.
	plain := makeQuery("a.example.com", dns.TypeA)
	pk, _ := dnsCacheKeyFor(plain)
	pk.do = key.do // same key apart from EDNS presence, which is not keyed

	resp, _, ok := c.get(pk, plain)
	if !ok {
		t.Fatal("expected hit")
	}

	if resp.IsEdns0() != nil {
		t.Fatal("non-EDNS client received an OPT record")
	}

	// A second EDNS client gets a fresh option-less OPT with its own size.
	q2 := makeQuery("a.example.com", dns.TypeA)
	q2.SetEdns0(8192, false)

	resp, _, ok = c.get(key, q2)
	if !ok {
		t.Fatal("expected hit")
	}

	opt := resp.IsEdns0()
	if opt == nil || len(opt.Option) != 0 {
		t.Fatalf("OPT = %v, want option-less OPT", opt)
	}

	if opt.UDPSize() != upstreamUDPSize {
		t.Fatalf("UDP size = %d, want clamp to %d", opt.UDPSize(), upstreamUDPSize)
	}
}

func TestDNSCache_Concurrent(t *testing.T) {
	h := newCacheHarness(t, policy.ActionBlock, []policy.Rule{allowFQDN("*.example.com", 443)}, 16)
	p := NewDNSProxy(h.cfg)

	alt := *h.pol
	alt.Version++ // distinct fingerprint so UpdatePolicy really flushes

	pols := []*policy.ResolvedPolicy{h.pol, &alt}

	var wg sync.WaitGroup

	for g := range 8 {
		wg.Go(func() {
			for i := range 40 {
				resp := h.query(fmt.Sprintf("h%d.example.com", (g+i)%24), dns.TypeA)
				if resp.Rcode != dns.RcodeSuccess {
					t.Errorf("rcode = %d", resp.Rcode)
				}

				if i%13 == 0 {
					p.UpdatePolicy(pols[(g+i)%2])
				}
			}
		})
	}

	wg.Wait()

	if h.entries() > 16 {
		t.Fatalf("entries = %d exceeds bound 16", h.entries())
	}
}
