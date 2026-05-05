package sinks

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// Prom counts violations, DNS queries, bytes sent, and advisories on
// the supplied Prometheus registry. Labels are kept low-cardinality on
// purpose: project_path is exposed (operator-controlled, bounded by
// scope count) but per-domain and per-IP labels are not — the operator
// can pull the detailed records from the NDJSON stdout sink when they
// need them.
type Prom struct {
	violations *prometheus.CounterVec
	dropped    *prometheus.CounterVec
	bytes      *prometheus.CounterVec
	dnsQueries *prometheus.CounterVec
	advisories *prometheus.CounterVec
}

// NewProm registers the CE counters on r and returns a sink.
func NewProm(r prometheus.Registerer) *Prom {
	const ns = "leitwacht_ce"

	p := &Prom{
		violations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "violations_total",
			Help: "Egress events that matched a deny / audit rule. " +
				"Counts both packet-layer drops (action=packet_dropped, " +
				"sinkhole_hit, etc.) and DNS-layer denials " +
				"(action=dns_blocked, dns_denied).",
		}, []string{"project_path", "action"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "violations_dropped_total",
			Help:      "Per-container violation reports dropped because the cap was hit.",
		}, []string{"project_path"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "egress_bytes_total",
			Help:      "Bytes observed leaving each container's netns.",
		}, []string{"project_path"}),
		dnsQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "dns_queries_total",
			Help: "DNS queries observed in each container's netns, " +
				"labelled by the proxy's verdict " +
				"(dns_allowed, dns_blocked, dns_observed, dns_denied).",
		}, []string{"project_path", "action"}),
		advisories: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "advisories_total",
			Help:      "Security advisories emitted by the agent.",
		}, []string{"kind"}),
	}

	r.MustRegister(p.violations, p.dropped, p.bytes, p.dnsQueries, p.advisories)
	return p
}

// isDNSDeny reports whether a DNS-layer activity action represents a
// policy denial — counted as a violation alongside packet-layer drops.
// `dns_observed` and `dns_allowed` are not denials.
func isDNSDeny(action string) bool {
	return action == "dns_blocked" || action == "dns_denied"
}

// ReportAsync increments the relevant counters for one container's
// egress report. DNS-blocked queries count toward both
// `dns_queries_total` (full DNS observability) and `violations_total`
// (operator's "how many things did leitwacht block" metric) — they
// represent the same event recorded in two places for ergonomics.
func (p *Prom) ReportAsync(
	_ context.Context,
	info enforcer.ContainerInfo,
	stats *enforcer.EgressStats,
	_ bool,
	_ time.Time,
) {
	if stats == nil {
		return
	}
	proj := info.ProjectPath
	p.bytes.WithLabelValues(proj).Add(float64(stats.TotalBytesSent))
	if stats.OverflowCount > 0 {
		p.dropped.WithLabelValues(proj).Add(float64(stats.OverflowCount))
	}
	for _, v := range stats.Violations {
		p.violations.WithLabelValues(proj, v.Action).Inc()
	}
	for _, d := range stats.DNSActivity {
		p.dnsQueries.WithLabelValues(proj, d.Action).Add(float64(d.QueryCount))
		if isDNSDeny(d.Action) {
			p.violations.WithLabelValues(proj, d.Action).Add(float64(d.QueryCount))
		}
	}
}

// ReportAdvisory increments the advisory counter.
func (p *Prom) ReportAdvisory(_ context.Context, a *advisory.Advisory) error {
	if a == nil {
		return nil
	}
	p.advisories.WithLabelValues(string(a.Kind)).Inc()
	return nil
}
