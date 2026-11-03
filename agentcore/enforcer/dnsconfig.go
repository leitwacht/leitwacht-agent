package enforcer

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
)

// DNS-config advisory recommendation codes.
const (
	// RecLowerNdots: a high ndots with several search domains makes
	// external names pay for every search suffix first; set ndots:2 in the
	// pod's dnsConfig.
	RecLowerNdots = "lower_ndots"
	// RecNodeSearchDomains: the search list carries suffixes outside the
	// cluster domain (inherited from the node, or injected); each external
	// lookup is also attempted under them.
	RecNodeSearchDomains = "node_search_domains"
)

const (
	// advisoryNdotsThreshold and advisorySearchThreshold gate the
	// lower_ndots recommendation: ndots >= 3 AND search count >= 2.
	advisoryNdotsThreshold  = 3
	advisorySearchThreshold = 2

	// maxAdvisorySuffixes and maxAdvisorySuffixLen bound the non-cluster
	// suffix names carried in the advisory payload.
	maxAdvisorySuffixes  = 6
	maxAdvisorySuffixLen = 253
)

// Example-name dot counts used for the amplification estimate:
// "registry.example.com" has 2 dots, "example.com" has 1.
const (
	exampleDots2 = 2
	exampleDots1 = 1
)

// DNSConfigObservation is the per-container resolver configuration derived
// at attach. All fields except NonClusterSuffixes are plain numbers; the
// suffix names come from the container-controlled resolv.conf and are
// sanitised (see sanitizeSuffixes) but must still be treated as untrusted
// when rendered.
type DNSConfigObservation struct {
	ContainerID string
	// ProjectPath / JobID / JobURL attribute the report (inherited from the
	// netns primary when the attaching container carries none).
	ProjectPath, JobID, JobURL string
	// Readable is false when resolv.conf could not be read (missing,
	// refused, FUSE), as opposed to read and empty.
	Readable bool
	// K8s is true when the container attached under a Kubernetes pod shape
	// or its search list has an entry under the cluster domain. The
	// recommendations are Kubernetes advice and are never given otherwise.
	K8s bool
	// SeenCount: reports of this exact config (ndots + search list) that
	// passed the per-netns gate since the previous delivery, including this
	// one (not a raw attach count).
	SeenCount int
	Ndots     int
	// NdotsExplicit is false when the resolver default (1) applies.
	NdotsExplicit bool
	SearchCount   int
	// NonClusterSearchCount counts search domains that are neither the
	// cluster domain nor a subdomain of it.
	NonClusterSearchCount int
	// ExtraQueries2Dot / ExtraQueries1Dot: extra lookups issued, per query
	// type, BEFORE the absolute try for a 2-dot ("registry.example.com") or
	// 1-dot ("example.com") name. See extraQueries.
	ExtraQueries2Dot int
	ExtraQueries1Dot int
	// NonClusterSuffixes: sanitised, capped copy of the non-cluster search
	// domains. Never logged; advisory payload only.
	NonClusterSuffixes []string
}

// extraQueries is the deterministic amplification estimate: resolvers treat
// a name with fewer than ndots dots as relative and try every search domain
// before the absolute name, so the extra lookups (per record type) equal the
// search-domain count; a name with at least ndots dots is tried absolute
// first and costs nothing extra on success.
func extraQueries(dots, ndots, searchCount int) int {
	if dots < ndots {
		return searchCount
	}

	return 0
}

// observeDNSConfig derives the observation. clusterDomain is configuration
// (empty means the default), never taken from the list.
func observeDNSConfig(containerID string, rc resolvConf, clusterDomain string, podShape bool) DNSConfigObservation {
	if clusterDomain == "" {
		clusterDomain = DefaultClusterDomain
	}

	var outside []string

	inCluster := false

	for _, s := range rc.search {
		if underDomain(s, clusterDomain) {
			inCluster = true
		} else {
			outside = append(outside, s)
		}
	}

	n := len(rc.search)

	return DNSConfigObservation{
		ContainerID:           containerID,
		Readable:              rc.readable,
		K8s:                   podShape || inCluster,
		SeenCount:             1,
		Ndots:                 rc.ndots,
		NdotsExplicit:         rc.ndotsExplicit,
		SearchCount:           n,
		NonClusterSearchCount: len(outside),
		ExtraQueries2Dot:      extraQueries(exampleDots2, rc.ndots, n),
		ExtraQueries1Dot:      extraQueries(exampleDots1, rc.ndots, n),
		NonClusterSuffixes:    sanitizeSuffixes(outside),
	}
}

// sanitizeSuffixes keeps only well-formed DNS names ([a-z0-9._-], no empty
// label, length-capped), at most maxAdvisorySuffixes.
func sanitizeSuffixes(in []string) []string {
	var out []string

	for _, s := range in {
		if len(out) == maxAdvisorySuffixes {
			break
		}

		if validSuffix(s) {
			out = append(out, s)
		}
	}

	return out
}

func validSuffix(s string) bool {
	if s == "" || len(s) > maxAdvisorySuffixLen {
		return false
	}

	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}

	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}

	return true
}

// Recommendation returns the advisory recommendation code, or "" when the
// configuration is not worth flagging: (ndots >= 3 AND >= 2 search domains)
// OR >= 1 non-cluster search domain. node_search_domains wins when both hold.
// Containers that are not Kubernetes-shaped never get one (their search
// lists, e.g. a LAN domain, are ordinary there).
func (o DNSConfigObservation) Recommendation() string {
	switch {
	case !o.K8s:
		return ""
	case o.NonClusterSearchCount >= 1:
		return RecNodeSearchDomains
	case o.Ndots >= advisoryNdotsThreshold && o.SearchCount >= advisorySearchThreshold:
		return RecLowerNdots
	}

	return ""
}

// Advisory builds the dns_config advisory, or nil when not worth flagging.
// The Message carries every field as key=value so a consumer that only
// understands the existing advisory wire shape (kind + message) still gets
// the full payload; Details carries the same values structured for sinks
// that can render them.
func (o DNSConfigObservation) Advisory() *advisory.Advisory {
	rec := o.Recommendation()
	if rec == "" {
		return nil
	}

	d := map[string]any{
		"ndots":                   o.Ndots,
		"ndots_explicit":          o.NdotsExplicit,
		"search_count":            o.SearchCount,
		"noncluster_search_count": o.NonClusterSearchCount,
		"extra_queries_2dot":      o.ExtraQueries2Dot,
		"extra_queries_1dot":      o.ExtraQueries1Dot,
		"seen_count":              o.SeenCount,
		"recommendation":          rec,
		"noncluster_suffixes":     append([]string(nil), o.NonClusterSuffixes...),
	}

	msg := "ndots=" + strconv.Itoa(o.Ndots) +
		" ndots_explicit=" + strconv.FormatBool(o.NdotsExplicit) +
		" search_count=" + strconv.Itoa(o.SearchCount) +
		" noncluster_search_count=" + strconv.Itoa(o.NonClusterSearchCount) +
		" extra_queries_2dot=" + strconv.Itoa(o.ExtraQueries2Dot) +
		" extra_queries_1dot=" + strconv.Itoa(o.ExtraQueries1Dot) +
		" seen_count=" + strconv.Itoa(o.SeenCount) +
		" recommendation=" + rec

	if len(o.NonClusterSuffixes) > 0 {
		msg += " noncluster_suffixes=" + strings.Join(o.NonClusterSuffixes, ",")
	}

	return &advisory.Advisory{
		ContainerID: o.ContainerID,
		ProjectPath: o.ProjectPath,
		JobID:       o.JobID,
		JobURL:      o.JobURL,
		Kind:        advisory.KindDNSConfig,
		Message:     msg,
		ActionTaken: "observed",
		Details:     d,
	}
}

// DNSConfigFunc receives a container's DNS configuration observation. It is
// called from a background worker goroutine (never the attach path), so it
// must be concurrency-safe and may block briefly; observations are queued up
// to dnsConfigQueueLen deep and dropped (counted) beyond that.
type DNSConfigFunc func(DNSConfigObservation)

const (
	dnsConfigQueueLen = 64
	// dnsConfigMinInterval rate-limits repeats of the same config.
	dnsConfigMinInterval = time.Hour
	// dnsConfigMaxFingerprints bounds the rate-limit table.
	dnsConfigMaxFingerprints = 1024
)

type dnsConfigSeen struct {
	last time.Time
	// lastAttributed: the last delivered report carried project attribution.
	lastAttributed bool
	// count: reports that passed the netns gate since (and including) the
	// last delivery decision.
	count int
}

// dnsConfigState is the Manager's dns_config reporting state: a lazily
// started bounded queue with one worker, and the per-fingerprint limiter.
type dnsConfigState struct {
	once     sync.Once
	queue    chan queuedDNSConfig
	done     chan struct{}
	stopOnce sync.Once
	dropped  atomic.Uint64

	mu   sync.Mutex
	seen map[[sha256.Size]byte]*dnsConfigSeen
}

type queuedDNSConfig struct {
	fn DNSConfigFunc
	o  DNSConfigObservation
}

func (s *dnsConfigState) start() {
	s.once.Do(func() {
		s.queue = make(chan queuedDNSConfig, dnsConfigQueueLen)
		s.done = make(chan struct{})

		go func() {
			for {
				select {
				case q := <-s.queue:
					q.fn(q.o)
				case <-s.done:
					return
				}
			}
		}()
	})
}

// stopDNSConfigWorker stops the worker; later observations are dropped.
func (m *Manager) stopDNSConfigWorker() {
	m.dnsCfg.start()
	m.dnsCfg.stopOnce.Do(func() { close(m.dnsCfg.done) })
}

// DNSConfigDropped returns how many observations were dropped (full queue
// or after shutdown).
func (m *Manager) DNSConfigDropped() uint64 { return m.dnsCfg.dropped.Load() }

// fingerprint identifies a config independent of the container.
func (rc resolvConf) fingerprint() [sha256.Size]byte {
	return sha256.Sum256([]byte(strconv.Itoa(rc.ndots) + "\x00" + strings.Join(rc.search, "\x00")))
}

// allow applies the per-fingerprint hourly limit and returns the seen count
// to report, or 0 when this occurrence is only counted. An attributed report
// is also allowed inside the interval when the last delivered one was
// unattributed (the K8s init sibling always comes first); an unattributed
// one only after the interval.
func (s *dnsConfigState) allow(fp [sha256.Size]byte, attributed bool, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seen == nil || len(s.seen) >= dnsConfigMaxFingerprints {
		if s.seen != nil {
			for k, v := range s.seen { // evict expired; reset if none were
				if now.Sub(v.last) >= dnsConfigMinInterval {
					delete(s.seen, k)
				}
			}
		}

		if s.seen == nil || len(s.seen) >= dnsConfigMaxFingerprints {
			s.seen = make(map[[sha256.Size]byte]*dnsConfigSeen)
		}
	}

	e := s.seen[fp]
	if e == nil {
		s.seen[fp] = &dnsConfigSeen{last: now, lastAttributed: attributed}

		return 1
	}

	e.count++

	if now.Sub(e.last) < dnsConfigMinInterval && (!attributed || e.lastAttributed) {
		return 0
	}

	n := e.count
	e.last, e.lastAttributed, e.count = now, attributed, 0

	return n
}

// SetOnDNSConfig sets the callback for advisory-worthy DNS configurations;
// see DNSConfigFunc for the concurrency contract. Set before the first Attach.
func (m *Manager) SetOnDNSConfig(fn DNSConfigFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.onDNSConfig = fn
}

// reportDNSConfig logs the observation (numbers and flags only: the
// resolv.conf is container-controlled, so no suffix name ever reaches the
// log) on every attach, then, at most once per netns and once per config per
// hour, queues advisory-worthy observations for the callback. Never blocks.
func (m *Manager) reportDNSConfig(nctx *NetnsContext, info ContainerInfo, rc resolvConf, podShape bool) {
	info = inheritProjectInfo(info, nctx)
	o := observeDNSConfig(info.ContainerID, rc, m.ClusterDomain, podShape)
	o.ProjectPath, o.JobID, o.JobURL = info.ProjectPath, info.JobID, info.JobURL

	m.logger.Info("dns config observed",
		"container_id", truncID(info.ContainerID),
		"readable", o.Readable,
		"ndots", o.Ndots,
		"ndots_explicit", o.NdotsExplicit,
		"search_count", o.SearchCount,
		"noncluster_search_count", o.NonClusterSearchCount,
		"extra_queries_2dot", o.ExtraQueries2Dot,
		"extra_queries_1dot", o.ExtraQueries1Dot,
	)

	m.mu.Lock()
	fn := m.onDNSConfig
	m.mu.Unlock()

	if fn == nil || o.Recommendation() == "" {
		return
	}

	attributed := info.ProjectPath != ""

	nctx.mu.Lock()
	skip := nctx.dnsCfgReported && (!attributed || nctx.dnsCfgReportedAttributed)
	if !skip {
		nctx.dnsCfgReported = true
		nctx.dnsCfgReportedAttributed = nctx.dnsCfgReportedAttributed || attributed
	}
	nctx.mu.Unlock()

	if skip {
		return
	}

	n := m.dnsCfg.allow(rc.fingerprint(), attributed, time.Now())
	if n == 0 {
		return
	}

	o.SeenCount = n

	m.dnsCfg.start()

	select {
	case <-m.dnsCfg.done:
		m.dnsCfg.dropped.Add(1)
	default:
		select {
		case m.dnsCfg.queue <- queuedDNSConfig{fn: fn, o: o}:
		default:
			m.dnsCfg.dropped.Add(1)
		}
	}
}
