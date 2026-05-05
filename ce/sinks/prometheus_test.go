package sinks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// TestPromCountersIncrement verifies that the leitwacht_ce_* counters
// observed via /metrics agree with the violation/advisory traffic the
// daemon reports. Operators rely on these counters for SLOs.
func TestPromCountersIncrement(t *testing.T) {
	r := prometheus.NewRegistry()
	p := NewProm(r)

	info := enforcer.ContainerInfo{
		ContainerID: "c1",
		ProjectPath: "team/app",
	}
	stats := &enforcer.EgressStats{
		TotalBytesSent: 2048,
		Violations: []enforcer.Violation{
			{Action: "packet_dropped"},
		},
		DNSActivity: []enforcer.DNSActivityEntry{
			{Domain: "evil.example.com", Action: "dns_blocked", QueryCount: 2},
			{Domain: "github.com", Action: "dns_allowed", QueryCount: 5},
			{Domain: "internal.example.com", Action: "dns_observed", QueryCount: 1},
		},
		OverflowCount: 1,
	}

	p.ReportAsync(context.Background(), info, stats, false, time.Time{})
	if err := p.ReportAdvisory(context.Background(), &advisory.Advisory{
		Kind: advisory.KindDinDDetected,
	}); err != nil {
		t.Fatalf("ReportAdvisory: %v", err)
	}

	wantBytes := `# HELP leitwacht_ce_egress_bytes_total Bytes observed leaving each container's netns.
# TYPE leitwacht_ce_egress_bytes_total counter
leitwacht_ce_egress_bytes_total{project_path="team/app"} 2048
`
	if err := testutil.GatherAndCompare(r, strings.NewReader(wantBytes),
		"leitwacht_ce_egress_bytes_total"); err != nil {
		t.Errorf("egress_bytes_total mismatch: %v", err)
	}

	wantViolations := `# HELP leitwacht_ce_violations_total Egress events that matched a deny / audit rule. Counts both packet-layer drops (action=packet_dropped, sinkhole_hit, etc.) and DNS-layer denials (action=dns_blocked, dns_denied).
# TYPE leitwacht_ce_violations_total counter
leitwacht_ce_violations_total{action="dns_blocked",project_path="team/app"} 2
leitwacht_ce_violations_total{action="packet_dropped",project_path="team/app"} 1
`
	if err := testutil.GatherAndCompare(r, strings.NewReader(wantViolations),
		"leitwacht_ce_violations_total"); err != nil {
		t.Errorf("violations_total mismatch: %v", err)
	}

	wantDNS := `# HELP leitwacht_ce_dns_queries_total DNS queries observed in each container's netns, labelled by the proxy's verdict (dns_allowed, dns_blocked, dns_observed, dns_denied).
# TYPE leitwacht_ce_dns_queries_total counter
leitwacht_ce_dns_queries_total{action="dns_allowed",project_path="team/app"} 5
leitwacht_ce_dns_queries_total{action="dns_blocked",project_path="team/app"} 2
leitwacht_ce_dns_queries_total{action="dns_observed",project_path="team/app"} 1
`
	if err := testutil.GatherAndCompare(r, strings.NewReader(wantDNS),
		"leitwacht_ce_dns_queries_total"); err != nil {
		t.Errorf("dns_queries_total mismatch: %v", err)
	}

	wantAdvisories := `# HELP leitwacht_ce_advisories_total Security advisories emitted by the agent.
# TYPE leitwacht_ce_advisories_total counter
leitwacht_ce_advisories_total{kind="dind_detected"} 1
`
	if err := testutil.GatherAndCompare(r, strings.NewReader(wantAdvisories),
		"leitwacht_ce_advisories_total"); err != nil {
		t.Errorf("advisories_total mismatch: %v", err)
	}

	wantOverflow := `# HELP leitwacht_ce_violations_dropped_total Per-container violation reports dropped because the cap was hit.
# TYPE leitwacht_ce_violations_dropped_total counter
leitwacht_ce_violations_dropped_total{project_path="team/app"} 1
`
	if err := testutil.GatherAndCompare(r, strings.NewReader(wantOverflow),
		"leitwacht_ce_violations_dropped_total"); err != nil {
		t.Errorf("violations_dropped_total mismatch: %v", err)
	}
}
