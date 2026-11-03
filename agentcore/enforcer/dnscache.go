package enforcer

import (
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// maxCachedResponseSize bounds the packed size of a cached response so a
// hostile or merely large answer cannot inflate memory use.
const maxCachedResponseSize = 1232

// DefaultDNSCacheSize is the per-proxy positive-answer cache capacity the
// CE daemon uses when nothing is configured. A DNSProxyConfig with
// CacheSize 0 has the cache disabled.
const DefaultDNSCacheSize = 1024

// dnsCacheKey identifies a cached answer. The DO and CD bits are part of
// the key so a DNSSEC-aware client never receives an answer cached for a
// client that did not ask for RRSIGs (or asked for different validation
// behaviour), and vice versa.
type dnsCacheKey struct {
	name   string // lowercased, no trailing dot
	qtype  uint16
	qclass uint16
	do     bool
	cd     bool
}

// dnsCacheEntry is one cached, already-filtered upstream answer.
type dnsCacheEntry struct {
	key     dnsCacheKey
	msg     *dns.Msg // filtered response template; never handed out directly
	ips     []string // A-record IPs the normal path would seed/record
	stored  time.Time
	expires time.Time
}

// DNSCacheStats is a point-in-time snapshot of a proxy's cache counters.
type DNSCacheStats struct {
	Hits    uint64
	Misses  uint64
	Entries int
}

// dnsCache is a bounded LRU of positive answers. It only ever stores
// responses that the proxy forwarded upstream, filtered, and would return
// to the client as a successful answer on an allow/forward path. The policy
// decision, event recording and allow-map seeding are NOT cached: they run
// on every query, hit or miss, so the cache only replaces the upstream
// round trip.
type dnsCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List // front = most recently used
	items map[dnsCacheKey]*list.Element
	gen   uint64 // bumped by flush; guards in-flight stores
	now   func() time.Time

	hits   atomic.Uint64
	misses atomic.Uint64
}

// newDNSCache returns a cache holding at most max entries, or nil (cache
// disabled) when max <= 0.
func newDNSCache(maxEntries int) *dnsCache {
	if maxEntries <= 0 {
		return nil
	}

	return &dnsCache{
		max:   maxEntries,
		ll:    list.New(),
		items: make(map[dnsCacheKey]*list.Element, maxEntries),
		now:   time.Now,
	}
}

// dnsCacheKeyFor derives the cache key from a client query. ok is false for
// queries that must bypass the cache (anything but a standard query with
// exactly one question).
func dnsCacheKeyFor(msg *dns.Msg) (dnsCacheKey, bool) {
	if len(msg.Question) != 1 || msg.Opcode != dns.OpcodeQuery {
		return dnsCacheKey{}, false
	}

	q := msg.Question[0]

	return dnsCacheKey{
		name:   strings.TrimSuffix(strings.ToLower(q.Name), "."),
		qtype:  q.Qtype,
		qclass: q.Qclass,
		do:     msg.IsEdns0() != nil && msg.IsEdns0().Do(),
		cd:     msg.CheckingDisabled,
	}, true
}

// generation returns the current flush generation. Read it before the
// upstream round trip and pass it to put.
func (c *dnsCache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.gen
}

// flush drops every entry and invalidates stores that began before it.
func (c *dnsCache) flush() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.gen++
	c.ll.Init()
	clear(c.items)
}

// stats returns the counters and current size.
func (c *dnsCache) stats() DNSCacheStats {
	if c == nil {
		return DNSCacheStats{}
	}

	c.mu.Lock()
	n := c.ll.Len()
	c.mu.Unlock()

	return DNSCacheStats{Hits: c.hits.Load(), Misses: c.misses.Load(), Entries: n}
}

// get returns a response for req built from a live cached entry: client
// message ID and question, TTLs decremented by the time spent in cache. A
// miss (or expired entry) returns ok=false and counts as a miss.
func (c *dnsCache) get(key dnsCacheKey, req *dns.Msg) (*dns.Msg, []string, bool) {
	now := c.now()

	c.mu.Lock()

	el, found := c.items[key]
	if !found {
		c.mu.Unlock()
		c.misses.Add(1)

		return nil, nil, false
	}

	e := el.Value.(*dnsCacheEntry) //nolint:forcetypeassert // list only holds *dnsCacheEntry
	if !now.Before(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		c.mu.Unlock()
		c.misses.Add(1)

		return nil, nil, false
	}

	c.ll.MoveToFront(el)
	c.mu.Unlock()

	// e.msg and e.ips are immutable after put; copy outside the lock.
	resp := e.msg.Copy()
	resp.Id = req.Id
	resp.Question = append([]dns.Question(nil), req.Question...)
	resp.RecursionDesired = req.RecursionDesired

	elapsed := uint32(now.Sub(e.stored) / time.Second)
	decrementTTLs(resp.Answer, elapsed)
	decrementTTLs(resp.Ns, elapsed)
	decrementTTLs(resp.Extra, elapsed)

	// The stored copy carries no OPT; mint a fresh one only for EDNS
	// clients, with no options (never echo another client's cookie, NSID
	// or padding).
	if opt := req.IsEdns0(); opt != nil {
		size := min(opt.UDPSize(), upstreamUDPSize)
		if size < dns.MinMsgSize {
			size = dns.MinMsgSize
		}

		resp.SetEdns0(size, opt.Do())
	}

	c.hits.Add(1)

	return resp, append([]string(nil), e.ips...), true
}

// decrementTTLs subtracts elapsed seconds from every record's TTL (floor 0).
// The EDNS OPT pseudo-record's "TTL" field carries flags and is left alone.
func decrementTTLs(rrs []dns.RR, elapsed uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}

		if h.Ttl > elapsed {
			h.Ttl -= elapsed
		} else {
			h.Ttl = 0
		}
	}
}

// cacheableTTL returns the cache lifetime for a filtered response, or 0 if
// the response is not cacheable: only NOERROR, non-truncated responses with
// at least one answer qualify. The lifetime is the minimum answer TTL,
// capped at maxResponseTTL.
func cacheableTTL(resp *dns.Msg) uint32 {
	if resp == nil || resp.Rcode != dns.RcodeSuccess || resp.Truncated || len(resp.Answer) == 0 {
		return 0
	}

	ttl := uint32(maxResponseTTL)
	for _, rr := range resp.Answer {
		if t := rr.Header().Ttl; t < ttl {
			ttl = t
		}
	}

	return ttl
}

// put stores a filtered upstream response. gen is the generation read before
// the upstream query; a flush in between discards the store. Ineligible
// responses (see cacheableTTL) are ignored.
func (c *dnsCache) put(key dnsCacheKey, resp *dns.Msg, ips []string, gen uint64) {
	ttl := cacheableTTL(resp)
	if ttl == 0 {
		return
	}

	stored := resp.Copy()
	stripOPT(stored)

	if stored.Len() > maxCachedResponseSize {
		return
	}

	now := c.now()
	e := &dnsCacheEntry{
		key:     key,
		msg:     stored,
		ips:     append([]string(nil), ips...),
		stored:  now,
		expires: now.Add(time.Duration(ttl) * time.Second),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if gen != c.gen {
		return
	}

	if el, found := c.items[key]; found {
		el.Value = e
		c.ll.MoveToFront(el)

		return
	}

	c.items[key] = c.ll.PushFront(e)

	for c.ll.Len() > c.max {
		oldest := c.ll.Back()
		c.ll.Remove(oldest)
		delete(c.items, oldest.Value.(*dnsCacheEntry).key) //nolint:forcetypeassert // see get
	}
}

// stripOPT removes the EDNS OPT pseudo-record(s) from m's additional section.
func stripOPT(m *dns.Msg) {
	kept := m.Extra[:0]

	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			kept = append(kept, rr)
		}
	}

	m.Extra = kept
}
