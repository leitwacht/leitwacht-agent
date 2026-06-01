// Package enforcer implements container-level network enforcement via eBPF, DNS proxy, and nftables.
package enforcer

import (
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
)

const (
	proxyListenPort = 15353
	upstreamTimeout = 2 * time.Second
	maxResponseTTL  = 300 // cap TTL in responses to 300s
	tcpReadTimeout  = 5 * time.Second
	tcpWriteTimeout = 5 * time.Second
	tcpMaxQueries   = 128

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

	// AddToAllowMap is called when a domain resolves to add {ip, port} to the eBPF map.
	// On non-Linux or in tests, this can be a no-op.
	AddToAllowMap func(ip net.IP, ports []int) error

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
			return attachedResponse(msg, qtype, cfg.AgentVersion)
		}

		if strings.HasPrefix(qname, reserved+".") {
			return nxdomainResponse(msg)
		}
	}

	rules := pol.RulesForJob("")

	match, matched := matchFirstRule(qname, rules)
	if matched {
		if match.Action == policy.ActionDeny {
			return handleDenyRule(msg, cfg, qname, qtype, match, recorder, pid, comm, parentComm, binaryPath, cgroupID, pol.Action == policy.ActionAudit)
		}

		return handleAllowRule(msg, cfg, qname, qtype, match, recorder, pid, comm, parentComm, binaryPath)
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

// matchFirstRule walks rules top to bottom and returns the first fqdn rule
// whose pattern matches qname. cidr rules are skipped (they feed the eBPF
// deny map, not the DNS proxy).
func matchFirstRule(qname string, rules []policy.Rule) (policy.Rule, bool) {
	for _, r := range rules {
		if r.PatternType != policy.PatternFQDN {
			continue
		}

		if matchesRule(qname, r) {
			return r, true
		}
	}

	return policy.Rule{}, false
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
	msg *dns.Msg, cfg *DNSProxyConfig, qname string, qtype uint16, rule policy.Rule,
	recorder *ViolationRecorder, pid uint32, comm, parentComm, binaryPath string,
) *dns.Msg {
	resp, ips, ok := forwardAndFilter(msg, cfg, qname, qtype)
	if !ok {
		return resp
	}

	if recorder != nil {
		recorder.RecordDNS(qname, dns.TypeToString[qtype], "dns_allowed", ips, pid, comm, parentComm, binaryPath)
	}

	seedAllowMap(cfg, ips, rule.Ports)

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
		cfg.Logger.Error("upstream dns failed", "domain", qname, "error", err)

		return servfailResponse(msg), nil, false
	}

	var (
		ips      []string
		filtered []dns.RR
	)

	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
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

// seedAllowMap adds the resolved IPs to the eBPF allow map on the given
// ports. No-op when AddToAllowMap is nil (tests / non-Linux hosts).
func seedAllowMap(cfg *DNSProxyConfig, ips []string, rulePorts []int) {
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

		addErr := cfg.AddToAllowMap(ip, ports)
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
		if err != nil {
			continue
		}
		// Retry over TCP if response was truncated.
		if resp.Truncated {
			tcpResp, _, tcpErr := tcpClient.Exchange(msg, upstream)
			if tcpErr == nil {
				return tcpResp, nil
			}
			// Fall through to return the truncated UDP response.
		}

		return resp, nil
	}

	return nil, fmt.Errorf("%w for %s", ErrAllUpstreamsFailed, msg.Question[0].Name)
}

// exchangeViaConn sends a DNS query over an existing UDP connection and reads
// the response. Retries on ID mismatch to skip stale responses from prior
// timed-out queries.
func exchangeViaConn(conn *net.UDPConn, msg *dns.Msg) (*dns.Msg, error) {
	// UDPSize must be set or ReadMsg defaults to a 512-byte buffer and
	// fails to parse larger upstream answers (see upstreamUDPSize).
	co := &dns.Conn{Conn: conn, UDPSize: upstreamUDPSize}

	deadlineErr := co.SetDeadline(time.Now().Add(upstreamTimeout))
	if deadlineErr != nil {
		return nil, fmt.Errorf("docker dns deadline: %w", deadlineErr)
	}

	writeErr := co.WriteMsg(msg)
	if writeErr != nil {
		return nil, fmt.Errorf("docker dns write: %w", writeErr)
	}

	for range 3 {
		resp, readErr := co.ReadMsg()
		if readErr != nil {
			return nil, fmt.Errorf("docker dns read: %w", readErr)
		}

		if resp.Id == msg.Id {
			return resp, nil
		}
	}

	return nil, ErrDockerDNSIDMismatch
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
	p := &DNSProxy{cfg: cfg}
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
