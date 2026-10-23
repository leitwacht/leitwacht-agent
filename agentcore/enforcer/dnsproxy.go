// Package enforcer implements container-level network enforcement via eBPF, DNS proxy, and nftables.
package enforcer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/wildcard"
)

var (
	// ErrAllUpstreamsFailed is returned when all upstream DNS servers fail to respond.
	ErrAllUpstreamsFailed = errors.New("all upstreams failed")
	// ErrDockerDNSIDMismatch is returned when the Docker DNS upstream returns
	// responses with mismatched IDs (stale packets from timed-out queries).
	ErrDockerDNSIDMismatch = errors.New("docker dns: id mismatch after retries")
	// ErrDNSQuestionMismatch is returned when an upstream reply does not
	// echo the question that was asked.
	ErrDNSQuestionMismatch = errors.New("dns reply question mismatch")
)

const (
	proxyListenPort = 15353
	upstreamTimeout = 2 * time.Second
	maxResponseTTL  = 300 // cap TTL in responses to 300s
	tcpReadTimeout  = 5 * time.Second
	tcpWriteTimeout = 5 * time.Second
	tcpMaxQueries   = 128

	// maxInflightQueries bounds concurrently-processed queries per proxy.
	// A job can fire packets as fast as it likes; beyond this the proxy
	// answers SERVFAIL immediately instead of spawning unbounded work
	// (goroutines, upstream sockets, log lines).
	maxInflightQueries = 256

	// maxUpstreamReads bounds how many non-matching datagrams one
	// upstream exchange will skip before giving up.
	maxUpstreamReads = 16

	// upstreamFailLogInterval rate-limits the upstream-failure log line.
	upstreamFailLogInterval = time.Second

	// upstreamUDPSize is the UDP receive-buffer size for upstream
	// responses. Without it the dns library defaults to MinMsgSize
	// (512), which silently truncates and fails to parse larger
	// answers — e.g. a multi-record A/AAAA set for a CDN-hosted name
	// (registry.npmjs.org AAAA is ~611 bytes). 4096 matches the common
	// EDNS0 buffer and fits any realistic response.
	upstreamUDPSize = 4096

	// SinkholeIPv4 is the RFC 5737 TEST-NET-1 address returned for
	// blocked A queries. Any attempt to connect to it is tagged as
	// a sinkhole_hit violation (the app ignored the DNS block). The
	// server-side reverse-IP map turns the ip back into the original
	// domain at ingest time.
	SinkholeIPv4 = "192.0.2.1"
	sinkholeTTL  = 30 // short TTL — apps don't pin after policy lifts

	// attachedIPv4 is the pinned A-record answer for queries
	// whose name appears in ReservedDomains. The
	// leitwacht-init init container greps for this address to confirm
	// the agent has attached DNS interception to the pod's netns.
	attachedIPv4 = "127.0.0.127"
	attachedTTL  = 5 // short TTL — stale cached negatives can't pin a post-attach pod into a false timeout
)

// DNSProxyConfig holds the configuration for a DNS proxy instance.
type DNSProxyConfig struct {
	Policy    *policy.ResolvedPolicy
	Upstreams []string // e.g., ["10.0.0.10:53", "1.1.1.1:53"]
	Logger    *slog.Logger

	// LookupRecorder resolves a per-container ViolationRecorder from a cgroup ID.
	// Returns nil if the cgroup is not (yet) registered.
	LookupRecorder func(cgroupID uint64) *ViolationRecorder

	// AddToAllowMap is called when a domain resolves to add {ip, port} to
	// the eBPF map, stamped with the matching rule's priority.
	// On non-Linux or in tests, this can be a no-op.
	AddToAllowMap func(ip net.IP, ports []int, prio uint32) error

	// LookupDNSPID returns the PID, process name, parent process name,
	// binary path, and cgroup ID for a DNS query from (netnsCookie,
	// srcPort). Populated by the eBPF DNS PID tracker; nil on non-Linux
	// or in tests. netnsCookie is cached once per DNSProxy instance via
	// getsockopt(SO_NETNS_COOKIE) on the container-netns-bound socket
	// (see (*DNSProxy).Start).
	LookupDNSPID func(netnsCookie uint64, srcPort uint16) (pid uint32, comm string, parentComm string, binaryPath string, cgroupID uint64)

	// DockerUpstream is a pre-bound, SO_MARK-ed UDP socket in the container
	// netns pointing at Docker's embedded DNS (127.0.0.11:53). Nil on K8s.
	DockerUpstream *net.UDPConn
	// DockerUpstreamMu serializes access to DockerUpstream. Non-nil when
	// DockerUpstream is set.
	DockerUpstreamMu *sync.Mutex

	// AgentVersion is echoed in the TXT record for attachedName.
	// Empty strings render as "unknown" — leaving this unset is not a bug.
	AgentVersion string

	// OnDNSViolation is called when a DNS query is blocked or denied in
	// block mode, providing an opportunity for immediate container kill.
	// Receives the cgroup ID, domain, and action string ("dns_blocked" or "dns_denied").
	// Nil by default — CE wires this in main.go. Not called in audit mode.
	OnDNSViolation func(cgroupID uint64, domain, action string)

	// EgressReady reports whether the cgroup_skb/egress program is attached
	// for this netns. The reserved attach-liveness reply is withheld
	// (NXDOMAIN, so the poller keeps waiting) until it returns true, so a
	// gated entrypoint cannot proceed before egress enforcement is live.
	// Nil means "no gating" (treated as ready) — preserves the prior
	// behaviour for any caller that doesn't wire it.
	EgressReady func() bool

	// upstreamFailLast / upstreamFailSuppressed rate-limit the
	// per-query upstream-failure log (unix nanos of the last emission,
	// and how many lines were swallowed since).
	upstreamFailLast       atomic.Int64
	upstreamFailSuppressed atomic.Int64
}

// HandleDNSQuery processes a single DNS query under ordered-rule policy.
// This is the core logic, separated from network I/O for testability.
// pol is the active policy snapshot (may be swapped at runtime via DNSProxy.UpdatePolicy).
// recorder is the per-container ViolationRecorder (may be nil during brief race windows).
// pid, comm, and parentComm identify the process that initiated the DNS query (0/""/"" if unknown).
//
// Evaluation is first-match-wins over the pol.RuleSets[""] ordered list
// (the server composes per-job lists; the agent's DNSProxy runs with a
// job-scoped view produced by (*ResolvedPolicy).ForJob()). If no rule
// matches and the project is in audit mode, the query forwards; in block
// mode it sinkholes without forwarding.
func HandleDNSQuery(
	msg *dns.Msg, cfg *DNSProxyConfig, pol *policy.ResolvedPolicy,
	recorder *ViolationRecorder, pid uint32, comm, parentComm, binaryPath string,
	cgroupID uint64,
) *dns.Msg {
	if len(msg.Question) == 0 {
		return refusedResponse(msg)
	}

	qname := strings.TrimSuffix(strings.ToLower(msg.Question[0].Name), ".")
	qtype := msg.Question[0].Qtype

	// Attachment liveness signal. Short-circuits policy matching and
	// activity recording — leitwacht-init init containers poll the
	// reserved name(s) independent of project enrollment and action
	// mode, and polling traffic should not pollute the DNS activity
	// log.
	//
	// The trailing-dot prefix branch handles K8s pod resolvers with
	// ndots:5 that walk the search list before trying the bare name.
	// The init uses the trailing-dot form to skip expansion, but
	// legacy inits and `dig` from inside a pod still produce variants.
	// Returning NXDOMAIN lets the resolver continue to the next
	// suffix (and eventually the FQDN) without recording the variant.
	for _, reserved := range ReservedDomains {
		if qname == reserved {
			// Withhold the attach-liveness signal until egress is actually
			// attached for this netns. NXDOMAIN (not the pinned A/TXT) keeps
			// the init/detonation poller waiting, so it cannot proceed in the
			// window after the DNS proxy starts but before AttachCgroup. Nil
			// EgressReady = no gating (prior behaviour).
			if cfg.EgressReady != nil && !cfg.EgressReady() {
				return nxdomainResponse(msg)
			}

			return attachedResponse(msg, qtype, cfg.AgentVersion)
		}

		if strings.HasPrefix(qname, reserved+".") {
			return nxdomainResponse(msg)
		}
	}

	rules := pol.RulesForJob("")

	match, matchIdx, matched := matchFirstRule(qname, rules)
	if matched {
		if match.Action == policy.ActionDeny {
			return handleDenyRule(msg, cfg, qname, qtype, match, recorder, pid, comm, parentComm, binaryPath, cgroupID, pol.Action == policy.ActionAudit)
		}

		return handleAllowRule(msg, cfg, qname, qtype, match, matchIdx, recorder, pid, comm, parentComm, binaryPath)
	}

	isAudit := pol.Action == policy.ActionAudit

	if !isAudit {
		if recorder != nil {
			recorder.RecordDNS(qname, dns.TypeToString[qtype], "dns_blocked", sinkholeIPsIfA(qtype), pid, comm, parentComm, binaryPath)
		}

		cfg.Logger.Debug("dns blocked", "domain", qname)

		if cfg.OnDNSViolation != nil {
			cfg.OnDNSViolation(cgroupID, qname, "dns_blocked")
		}

		return sinkholeResponse(msg)
	}

	return forwardAndObserve(msg, cfg, qname, qtype, recorder, pid, comm, parentComm, binaryPath)
}

// matchFirstRule walks rules top to bottom and returns the first fqdn
// rule whose pattern matches qname, along with its index in the list.
//
// cidr rules are skipped here — they have no name to match against and
// are enforced in the datapath instead (installed at attach into the
// allow/deny maps). The returned index is what keeps the two halves
// consistent: it becomes the priority of every allow-map entry this
// resolution seeds, so an IP rule sitting above this fqdn rule still
// wins in egress.c.
func matchFirstRule(qname string, rules []policy.Rule) (policy.Rule, int, bool) {
	for i, r := range rules {
		if r.PatternType != policy.PatternFQDN {
			continue
		}

		if matchesRule(qname, r) {
			return r, i, true
		}
	}

	return policy.Rule{}, -1, false
}

// matchesRule chooses wildcard semantics per action: allow rules use
// single-label matching (Cilium-style, safer default); deny rules use
// suffix matching (any-depth) so `*.svc.cluster.local` catches k8s
// search-path variants.
func matchesRule(qname string, r policy.Rule) bool {
	if r.Action == policy.ActionDeny {
		return wildcard.MatchesSuffix(qname, r.Pattern)
	}

	return wildcard.MatchesSingle(qname, r.Pattern)
}

// handleDenyRule returns the right DNS response for a matching deny rule:
// NXDOMAIN when resolution=nxdomain (k8s search-path cleanup), sinkhole
// A record otherwise (forensic signal on follow-up connect).
func handleDenyRule(
	msg *dns.Msg, cfg *DNSProxyConfig, qname string, qtype uint16, rule policy.Rule,
	recorder *ViolationRecorder, pid uint32, comm, parentComm, binaryPath string,
	cgroupID uint64, isAudit bool,
) *dns.Msg {
	useNXDomain := rule.Resolution == policy.DenyResolutionNXDomain

	if recorder != nil {
		var resolvedIPs []string
		if !useNXDomain {
			resolvedIPs = sinkholeIPsIfA(qtype)
		}

		recorder.RecordDNS(qname, dns.TypeToString[qtype], "dns_denied", resolvedIPs, pid, comm, parentComm, binaryPath)
	}

	cfg.Logger.Debug("dns denied", "domain", qname, "pattern", rule.Pattern, "resolution", rule.Resolution)

	if cfg.OnDNSViolation != nil && !isAudit {
		cfg.OnDNSViolation(cgroupID, qname, "dns_denied")
	}

	if useNXDomain {
		return nxdomainResponse(msg)
	}

	return sinkholeResponse(msg)
}

// handleAllowRule forwards the query upstream, strips AAAA, and seeds the
// eBPF allow map with the A-record IPs on the rule's permitted ports.
func handleAllowRule(
	msg *dns.Msg, cfg *DNSProxyConfig, qname string, qtype uint16, rule policy.Rule, ruleIdx int,
	recorder *ViolationRecorder, pid uint32, comm, parentComm, binaryPath string,
) *dns.Msg {
	resp, ips, ok := forwardAndFilter(msg, cfg, qname, qtype)
	if !ok {
		return resp
	}

	if recorder != nil {
		recorder.RecordDNS(qname, dns.TypeToString[qtype], "dns_allowed", ips, pid, comm, parentComm, binaryPath)
	}

	seedAllowMap(cfg, ips, rule.Ports, policy.RulePriority(ruleIdx))

	return resp
}

// forwardAndObserve handles the audit-mode no-match path: forward, strip
// AAAA, record as dns_observed (no allow-map seed — there's no policy
// saying these IPs should be reachable, they're just under observation).
func forwardAndObserve(
	msg *dns.Msg, cfg *DNSProxyConfig, qname string, qtype uint16,
	recorder *ViolationRecorder, pid uint32, comm, parentComm, binaryPath string,
) *dns.Msg {
	resp, ips, ok := forwardAndFilter(msg, cfg, qname, qtype)
	if !ok {
		return resp
	}

	if recorder != nil {
		recorder.RecordDNS(qname, dns.TypeToString[qtype], "dns_observed", ips, pid, comm, parentComm, binaryPath)
	}

	cfg.Logger.Debug("dns observed (audit)", "domain", qname, "type", dns.TypeToString[qtype])

	return resp
}

// forwardAndFilter proxies the query upstream, strips AAAA answers, and
// returns the filtered response plus the A-record IPs seen. Returns
// ok=false (and a SERVFAIL response) if the upstream failed.
func forwardAndFilter(msg *dns.Msg, cfg *DNSProxyConfig, qname string, qtype uint16) (*dns.Msg, []string, bool) {
	_ = qtype // reserved for future qtype-specific handling (e.g., HTTPS/SVCB)

	resp, err := forwardQuery(msg, cfg)
	if err != nil {
		logUpstreamFailure(cfg, err)

		return servfailResponse(msg), nil, false
	}

	var (
		ips      []string
		filtered []dns.RR
	)

	// Only A records owned by the queried name or by a name in its
	// validated CNAME chain are trusted (returned and seeded). Anything
	// else in the answer section is injected data, not an answer to this
	// question.
	chain := cnameChain(qname, resp.Answer)

	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if !chain[canonicalName(r.Hdr.Name)] {
				cfg.Logger.Debug("dropped out-of-chain A record")

				continue
			}

			ips = append(ips, r.A.String())
			capTTL(r.Header())

			filtered = append(filtered, rr)
		case *dns.AAAA:
			cfg.Logger.Debug("stripped AAAA", "domain", qname, "ipv6", r.AAAA.String())

			continue
		default:
			filtered = append(filtered, rr)
		}
	}

	resp.Answer = filtered

	return resp, ips, true
}

// canonicalName lowercases a DNS name and strips the trailing root dot.
func canonicalName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// cnameChain returns the set of owner names reachable from qname by
// following CNAME records present in answers (qname itself included).
func cnameChain(qname string, answers []dns.RR) map[string]bool {
	chain := map[string]bool{canonicalName(qname): true}

	for range len(answers) {
		grew := false

		for _, rr := range answers {
			cn, ok := rr.(*dns.CNAME)
			if !ok || !chain[canonicalName(cn.Hdr.Name)] {
				continue
			}

			target := canonicalName(cn.Target)
			if !chain[target] {
				chain[target] = true
				grew = true
			}
		}

		if !grew {
			break
		}
	}

	return chain
}

// logUpstreamFailure logs an upstream failure at most once per
// upstreamFailLogInterval, at Debug and without the queried name (which
// is attacker-chosen), so a query flood cannot flood the log.
func logUpstreamFailure(cfg *DNSProxyConfig, err error) {
	now := time.Now().UnixNano()

	last := cfg.upstreamFailLast.Load()
	if now-last < int64(upstreamFailLogInterval) || !cfg.upstreamFailLast.CompareAndSwap(last, now) {
		cfg.upstreamFailSuppressed.Add(1)

		return
	}

	cfg.Logger.Debug("upstream dns failed", "error", err,
		"suppressed", cfg.upstreamFailSuppressed.Swap(0))
}

// seedAllowMap adds the resolved IPs to the eBPF allow map on the given
// ports, stamped with the priority of the rule that authorised them.
// No-op when AddToAllowMap is nil (tests / non-Linux hosts).
func seedAllowMap(cfg *DNSProxyConfig, ips []string, rulePorts []int, prio uint32) {
	if cfg.AddToAllowMap == nil {
		return
	}

	ports := rulePorts
	if len(ports) == 0 {
		ports = []int{443, 80}
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		addErr := cfg.AddToAllowMap(ip, ports, prio)
		if addErr != nil {
			cfg.Logger.Error("add to allow map", "ip", ipStr, "error", addErr)
		}
	}
}

func forwardQuery(msg *dns.Msg, cfg *DNSProxyConfig) (*dns.Msg, error) {
	// Try Docker upstream first (pre-bound marked socket in container netns).
	if cfg.DockerUpstream != nil {
		cfg.DockerUpstreamMu.Lock()
		resp, err := exchangeViaConn(cfg.DockerUpstream, msg)
		cfg.DockerUpstreamMu.Unlock()

		if err == nil {
			return resp, nil
		}
		// Fall through to regular upstreams on error.
	}

	udpClient := &dns.Client{Timeout: upstreamTimeout, Net: "udp", UDPSize: upstreamUDPSize}
	tcpClient := &dns.Client{Timeout: upstreamTimeout, Net: "tcp"}

	for _, upstream := range cfg.Upstreams {
		resp, _, err := udpClient.Exchange(msg, upstream)
		if err != nil || !questionMatches(msg, resp) {
			continue
		}
		// Retry over TCP if response was truncated.
		if resp.Truncated {
			tcpResp, _, tcpErr := tcpClient.Exchange(msg, upstream)
			if tcpErr == nil && questionMatches(msg, tcpResp) {
				return tcpResp, nil
			}
			// Fall through to return the truncated UDP response.
		}

		return resp, nil
	}

	return nil, fmt.Errorf("%w", ErrAllUpstreamsFailed)
}

// exchangeViaConn sends a DNS query over an existing UDP connection and reads
// the response. The upstream socket lives in the job's netns, so the job can
// race forged datagrams at it: the query goes out under a fresh random ID
// (not the client's, which the job knows), and a reply is accepted only if it
// carries that ID AND echoes the question. Non-matching datagrams are
// skipped; the client's original ID is restored on the accepted reply.
func exchangeViaConn(conn *net.UDPConn, msg *dns.Msg) (*dns.Msg, error) {
	// UDPSize must be set or ReadMsg defaults to a 512-byte buffer and
	// fails to parse larger upstream answers (see upstreamUDPSize).
	co := &dns.Conn{Conn: conn, UDPSize: upstreamUDPSize}

	deadlineErr := co.SetDeadline(time.Now().Add(upstreamTimeout))
	if deadlineErr != nil {
		return nil, fmt.Errorf("docker dns deadline: %w", deadlineErr)
	}

	upID, idErr := randomDNSID()
	if idErr != nil {
		return nil, fmt.Errorf("docker dns id: %w", idErr)
	}

	out := msg.Copy()
	out.Id = upID

	writeErr := co.WriteMsg(out)
	if writeErr != nil {
		return nil, fmt.Errorf("docker dns write: %w", writeErr)
	}

	sawBadQuestion := false

	for range maxUpstreamReads {
		resp, readErr := co.ReadMsg()
		if readErr != nil {
			return nil, fmt.Errorf("docker dns read: %w", readErr)
		}

		if resp.Id != upID {
			continue
		}

		if !questionMatches(msg, resp) {
			sawBadQuestion = true

			continue
		}

		resp.Id = msg.Id

		return resp, nil
	}

	if sawBadQuestion {
		return nil, ErrDNSQuestionMismatch
	}

	return nil, ErrDockerDNSIDMismatch
}

// randomDNSID returns a cryptographically random 16-bit DNS message ID.
func randomDNSID() (uint16, error) {
	var b [2]byte

	_, err := rand.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("read random: %w", err)
	}

	return binary.BigEndian.Uint16(b[:]), nil
}

// questionMatches reports whether resp echoes exactly the question of req
// (name case-insensitively, type and class exactly).
func questionMatches(req, resp *dns.Msg) bool {
	if len(req.Question) != 1 || len(resp.Question) != 1 {
		return false
	}

	rq, pq := req.Question[0], resp.Question[0]

	return rq.Qtype == pq.Qtype && rq.Qclass == pq.Qclass &&
		strings.EqualFold(rq.Name, pq.Name)
}

func capTTL(hdr *dns.RR_Header) {
	if hdr.Ttl > maxResponseTTL {
		hdr.Ttl = maxResponseTTL
	}
}

func nxdomainResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)

	return resp
}

// sinkholeResponse synthesises an A record pointing at SinkholeIPv4 for
// blocked A queries. Non-A qtypes fall back to NXDOMAIN — AAAA is already
// stripped by the allow path and IPv6 is intentionally disabled, so we
// don't manufacture an IPv6 sinkhole.
func sinkholeResponse(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeA {
		return nxdomainResponse(req)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    sinkholeTTL,
			},
			A: net.ParseIP(SinkholeIPv4).To4(),
		},
	}

	return resp
}

// sinkholeIPsIfA returns [SinkholeIPv4] for A queries and nil otherwise.
// Persisting the sinkhole IP in DNSActivityEntry.ResolvedIPs lets the
// server's BuildDNSReverseMap map the sinkhole IP back to the originally
// blocked domain when a sinkhole_hit violation comes in.
func sinkholeIPsIfA(qtype uint16) []string {
	if qtype == dns.TypeA {
		return []string{SinkholeIPv4}
	}

	return nil
}

// attachedResponse synthesises the attachment-liveness reply the
// leitwacht-init init container polls for. A queries get a pinned 127.0.0.127
// answer (what the init's shell loop grep-matches); TXT queries get a
// human-readable "attached version=<ver>" answer for operator debugging
// (dig from inside a running pod). AAAA and other qtypes get NOERROR with
// empty answer — NOT NXDOMAIN, because NXDOMAIN would tell the resolver
// "this name has no records of any type" and poison negative caches.
func attachedResponse(req *dns.Msg, qtype uint16, agentVersion string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)

	hdr := dns.RR_Header{
		Name:  req.Question[0].Name,
		Class: dns.ClassINET,
		Ttl:   attachedTTL,
	}

	switch qtype {
	case dns.TypeA:
		ahdr := hdr
		ahdr.Rrtype = dns.TypeA
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: ahdr,
				A:   net.ParseIP(attachedIPv4).To4(),
			},
		}
	case dns.TypeTXT:
		ver := agentVersion
		if ver == "" {
			ver = "unknown"
		}

		thdr := hdr
		thdr.Rrtype = dns.TypeTXT
		resp.Answer = []dns.RR{
			&dns.TXT{
				Hdr: thdr,
				Txt: []string{"attached version=" + ver},
			},
		}
	}

	return resp
}

func servfailResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)

	return resp
}

func refusedResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeRefused)

	return resp
}

// DNSProxy is a DNS server that intercepts queries inside a container's netns
// and applies allowlist policy. Sockets are pre-bound in the container netns,
// but the server goroutines run in the host netns. The policy can be swapped
// at runtime via UpdatePolicy (e.g., when a build container joins a netns
// previously prepared by a sibling helper container).
type DNSProxy struct {
	cfg         *DNSProxyConfig
	policy      atomic.Pointer[policy.ResolvedPolicy]
	udpServer   *dns.Server
	tcpServer   *dns.Server
	udpConn     net.PacketConn
	tcpListener net.Listener
	wg          sync.WaitGroup

	// sem bounds in-flight queries (see maxInflightQueries).
	sem chan struct{}

	// netnsCookie identifies the netns the proxy's bound sockets live
	// in. Populated once in Start() via getsockopt(SO_NETNS_COOKIE) on
	// udpConn and passed to LookupDNSPID for every query. Zero if the
	// lookup failed (pre-5.14 kernels, non-Linux tests, or permission
	// issues) — the BPF side writes with the kernel-observed cookie,
	// so a zero userspace cookie simply misses every lookup, which
	// degrades to no-attribution rather than wrong attribution.
	netnsCookie uint64
}

// NewDNSProxy creates a proxy with the given config.
func NewDNSProxy(cfg *DNSProxyConfig) *DNSProxy {
	p := &DNSProxy{cfg: cfg, sem: make(chan struct{}, maxInflightQueries)}
	p.policy.Store(cfg.Policy)

	return p
}

// UpdatePolicy atomically swaps the active policy. Queries already in flight
// use the old policy; subsequent queries use the new one.
func (p *DNSProxy) UpdatePolicy(pol *policy.ResolvedPolicy) {
	p.policy.Store(pol)
}

// Start begins serving DNS on pre-bound sockets. The sockets must have been
// created inside the container's network namespace; the serving goroutines
// run in the host namespace so upstream queries use the host network.
func (p *DNSProxy) Start(udpConn net.PacketConn, tcpListener net.Listener) {
	p.udpConn = udpConn
	p.tcpListener = tcpListener

	// Cache the netns cookie of the container-netns-bound UDP socket.
	// BPF-side writes key on bpf_get_netns_cookie(NULL) of the client
	// task, which lives in the same netns as this socket — so caching
	// once at Start() and reusing per query is correct. Zero on failure
	// (degrades to no-attribution, never mis-attribution).
	p.netnsCookie = netnsCookieFromConn(udpConn, p.cfg.Logger)

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		select {
		case p.sem <- struct{}{}:
			defer func() { <-p.sem }()
		default:
			// Saturated: shed load rather than queue unbounded work.
			_ = w.WriteMsg(servfailResponse(r))

			return
		}

		var (
			pid        uint32
			comm       string
			parentComm string
			binaryPath string
			cgroupID   uint64
		)

		if p.cfg.LookupDNSPID != nil {
			var port int

			switch addr := w.RemoteAddr().(type) {
			case *net.UDPAddr:
				port = addr.Port
			case *net.TCPAddr:
				port = addr.Port
			}

			if port != 0 {
				pid, comm, parentComm, binaryPath, cgroupID = p.cfg.LookupDNSPID(p.netnsCookie, uint16(port))
			}
		}

		var recorder *ViolationRecorder
		if p.cfg.LookupRecorder != nil {
			recorder = p.cfg.LookupRecorder(cgroupID)
		}

		pol := p.policy.Load()

		resp := HandleDNSQuery(r, p.cfg, pol, recorder, pid, comm, parentComm, binaryPath, cgroupID)
		if resp != nil {
			_ = w.WriteMsg(resp)
		}
	})

	p.udpServer = &dns.Server{
		PacketConn: udpConn,
		Handler:    handler,
	}
	p.tcpServer = &dns.Server{
		Listener:      tcpListener,
		Handler:       handler,
		ReadTimeout:   tcpReadTimeout,
		WriteTimeout:  tcpWriteTimeout,
		MaxTCPQueries: tcpMaxQueries,
	}

	p.wg.Add(2)

	go func() {
		defer p.wg.Done()

		_ = p.udpServer.ActivateAndServe()
	}()

	go func() {
		defer p.wg.Done()

		_ = p.tcpServer.ActivateAndServe()
	}()
}

// Stop shuts down both UDP and TCP servers.
func (p *DNSProxy) Stop() {
	// Close the underlying connections to unblock ActivateAndServe.
	if p.udpConn != nil {
		_ = p.udpConn.Close()
	}

	if p.tcpListener != nil {
		_ = p.tcpListener.Close()
	}

	p.wg.Wait()
}
