package enforcer

import "sync"

// DNSCache is a netns-lifetime IP → domain map populated by the DNS
// proxy each time a query resolves. Used at pre-flush reconciliation
// to attribute bare-IP packet violations against the domain that
// resolved them — eliminating the server-side race where concurrent
// packet and DNS reports could leave violations permanently bare.
//
// Lives for the lifetime of the NetnsContext (not reset per bucket).
// Shared across all cgroup recorders in the same netns so sibling
// containers (helper + build) benefit from each other's DNS.
//
// Bounded via maxDNSCacheEntries. At the cap, new entries are
// silently dropped. A ~10k cap easily covers a CI job's DNS surface
// even for renovate-sized dependency walks.
type DNSCache struct {
	mu sync.RWMutex
	m  map[string]string
}

// maxDNSCacheEntries bounds memory for long-running jobs that
// resolve many IPs (CDN rotation, wildcard-heavy renovate runs).
const maxDNSCacheEntries = 10000

// NewDNSCache returns an empty cache ready for use.
func NewDNSCache() *DNSCache {
	return &DNSCache{m: make(map[string]string)}
}

// Record associates each IP in ips with domain. Last-write-wins on
// conflict — mirrors the server's BuildDNSReverseMap semantics so
// behaviour is consistent whether reconciliation happens agent-side
// or (as a fallback) server-side. Nil receiver is a safe no-op so
// tests and stub paths can skip constructing a cache.
func (c *DNSCache) Record(domain string, ips []string) {
	if c == nil || domain == "" || len(ips) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ip := range ips {
		if ip == "" {
			continue
		}

		if _, exists := c.m[ip]; !exists && len(c.m) >= maxDNSCacheEntries {
			return
		}

		c.m[ip] = domain
	}
}

// Lookup returns the cached domain for ip, or "" if the IP was never
// observed in a DNS response.
func (c *DNSCache) Lookup(ip string) string {
	if c == nil || ip == "" {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.m[ip]
}

// Len returns the number of cached IPs. Used by tests and diagnostics.
func (c *DNSCache) Len() int {
	if c == nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.m)
}
