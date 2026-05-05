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
