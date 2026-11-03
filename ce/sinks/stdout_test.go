package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// TestStdoutEmitsNDJSON verifies that violation reports and advisories
// produced by the agent come out as one JSON object per line on the
// configured writer, with the expected field set. CE operators rely on
// this shape for their NDJSON consumers (Loki, Vector, etc.).
func TestStdoutEmitsNDJSON(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdout(&buf, "node-1", slog.Default())

	info := enforcer.ContainerInfo{
		ContainerID: "abcdef0123456789",
		ProjectPath: "team/app",
		JobID:       "42",
		JobName:     "build",
		JobURL:      "https://gitlab.example.com/team/app/-/jobs/42",
		Action:      "block",
	}
	stats := &enforcer.EgressStats{
		TotalBytesSent: 12345,
		Violations: []enforcer.Violation{{
			Domain:    "evil.example.com",
			Action:    "dns_blocked",
			Timestamp: time.Now().UTC(),
		}},
	}

	sink.ReportAsync(context.Background(), info, stats, false, time.Time{})

	if err := sink.ReportAdvisory(context.Background(), &advisory.Advisory{
		ContainerID: "abcdef0123456789",
		ProjectPath: "team/app",
		Kind:        advisory.KindDinDDetected,
		Message:     "DOCKER_HOST=tcp:// detected",
		ActionTaken: "warned",
	}); err != nil {
		t.Fatalf("ReportAdvisory: %v", err)
	}

	// Close drains the async queue and waits for the writer to flush.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d (%q)", len(lines), buf.String())
	}

	var v map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &v); err != nil {
		t.Fatalf("violation NDJSON parse: %v", err)
	}
	if v["type"] != "violation_report" {
		t.Errorf("violation type = %v, want violation_report", v["type"])
	}
	if v["hostname"] != "node-1" {
		t.Errorf("hostname = %v, want node-1", v["hostname"])
	}
	if v["project_path"] != "team/app" {
		t.Errorf("project_path = %v, want team/app", v["project_path"])
	}

	var a map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &a); err != nil {
		t.Fatalf("advisory NDJSON parse: %v", err)
	}
	if a["type"] != "advisory" {
		t.Errorf("advisory type = %v, want advisory", a["type"])
	}
	if a["kind"] != string(advisory.KindDinDDetected) {
		t.Errorf("kind = %v, want %v", a["kind"], advisory.KindDinDDetected)
	}
}

func TestStdoutRendersDNSConfigAdvisory(t *testing.T) {
	var buf bytes.Buffer

	sink := NewStdout(&buf, "node-1", slog.Default())

	o := enforcer.DNSConfigObservation{
		ContainerID: "abc", K8s: true, Ndots: 5, NdotsExplicit: true, SearchCount: 3,
		NonClusterSearchCount: 1, ExtraQueries2Dot: 3, ExtraQueries1Dot: 3,
		NonClusterSuffixes: []string{"ec2.internal"},
	}

	a := o.Advisory()
	if a == nil {
		t.Fatal("no advisory")
	}

	if err := sink.ReportAdvisory(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	var v map[string]any
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("%v: %q", err, buf.String())
	}

	d, _ := v["details"].(map[string]any)
	if v["kind"] != "dns_config" || v["action_taken"] != "observed" || d == nil ||
		d["ndots"] != float64(5) || d["recommendation"] != "node_search_domains" ||
		d["extra_queries_2dot"] != float64(3) {
		t.Fatalf("unexpected record: %v", v)
	}

	sfx, _ := d["noncluster_suffixes"].([]any)
	if len(sfx) != 1 || sfx[0] != "ec2.internal" {
		t.Fatalf("suffixes: %v", d["noncluster_suffixes"])
	}

	if !strings.Contains(v["message"].(string), "ndots=5") {
		t.Fatalf("message: %v", v["message"])
	}
}
