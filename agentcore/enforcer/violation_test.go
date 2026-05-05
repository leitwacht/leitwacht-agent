package enforcer

import (
	"testing"
	"time"
)

func TestViolationRecorder_Basic(t *testing.T) {
	r := NewViolationRecorder(nil)

	r.RecordViolation(Violation{Domain: "evil.com", Action: "dns_blocked", Timestamp: time.Now()})
	r.RecordDNS("pypi.org", "A", "dns_allowed", []string{"1.2.3.4", "5.6.7.8"}, 42, "node", "npm", "")
	r.RecordDNS("pypi.org", "A", "dns_allowed", []string{"1.2.3.4", "9.10.11.12"}, 43, "curl", "pip", "") // merge IPs, keep first PID

	violations, activity := r.Snapshot()
	if len(violations) != 1 {
		t.Fatalf("violations = %d", len(violations))
	}
	if len(activity) != 1 {
		t.Fatalf("activity = %d", len(activity))
	}
	if activity[0].QueryCount != 2 {
		t.Fatalf("query_count = %d", activity[0].QueryCount)
	}
	if len(activity[0].ResolvedIPs) != 3 {
		t.Fatalf("resolved_ips = %d, want 3", len(activity[0].ResolvedIPs))
	}
	// First-seen process attribution is preserved through snapshot.
	if activity[0].PID != 42 {
		t.Fatalf("pid = %d, want 42", activity[0].PID)
	}
	if activity[0].Comm != "node" {
		t.Fatalf("comm = %q, want %q", activity[0].Comm, "node")
	}
	if activity[0].ParentComm != "npm" {
		t.Fatalf("parent_comm = %q, want %q", activity[0].ParentComm, "npm")
	}
}

func TestViolationRecorder_PacketStaysRawWithoutCache(t *testing.T) {
	// Nil cache → no agent-side reconciliation; violation ships bare
	// and the server-side backfill handles it (legacy path, kept as
	// safety net for nil-cache codepaths like buildkit tests).
	r := NewViolationRecorder(nil)

	r.RecordDNS("example.com", "A", "dns_allowed", []string{"1.2.3.4"}, 1, "curl", "bash", "")
	r.RecordViolation(Violation{IP: "1.2.3.4", Port: 8443, Action: "packet_observed", Timestamp: time.Now()})

	violations, _ := r.Snapshot()
	if len(violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(violations))
	}

	if violations[0].Domain != "" {
		t.Fatalf("domain = %q, want empty (nil cache skips reconciliation)", violations[0].Domain)
	}
}

// With a cache, RecordDNS populates it and SnapshotAndReset attributes
// previously-bare violations to the resolving domain before returning.
// This is the agent-side reconciliation that closes the server-side race.
func TestViolationRecorder_ReconcilesBareViolationsViaCache(t *testing.T) {
	cache := NewDNSCache()
	r := NewViolationRecorder(cache)

	r.RecordDNS("example.com", "A", "dns_allowed", []string{"1.2.3.4"}, 1, "curl", "bash", "")
	r.RecordViolation(Violation{IP: "1.2.3.4", Port: 443, Action: "packet_observed", Timestamp: time.Now()})
	r.RecordViolation(Violation{IP: "9.9.9.9", Port: 443, Action: "packet_observed", Timestamp: time.Now()})

	violations, _, _ := r.SnapshotAndReset()
	if len(violations) != 2 {
		t.Fatalf("violations = %d, want 2", len(violations))
	}

	var reconciled, stillBare int
	for _, v := range violations {
		switch {
		case v.IP == "1.2.3.4" && v.Domain == "example.com":
			reconciled++
		case v.IP == "9.9.9.9" && v.Domain == "":
			stillBare++
		default:
			t.Errorf("unexpected violation shape: ip=%s domain=%q", v.IP, v.Domain)
		}
	}

	if reconciled != 1 {
		t.Errorf("reconciled = %d, want 1", reconciled)
	}

	if stillBare != 1 {
		t.Errorf("still-bare = %d, want 1 (9.9.9.9 has no matching DNS)", stillBare)
	}
}

// A cache shared across two recorders — the shape used per-netns where
// the sibling packet recorder consults the DNS recorder's observations.
func TestViolationRecorder_SharedCacheAcrossRecorders(t *testing.T) {
	cache := NewDNSCache()

	dnsRec := NewViolationRecorder(cache)    // sharedDNSRecorder equivalent
	packetRec := NewViolationRecorder(cache) // per-cgroup equivalent

	dnsRec.RecordDNS("howett.net", "A", "dns_allowed", []string{"13.77.158.121"}, 1, "node", "renovate", "")
	packetRec.RecordViolation(Violation{IP: "13.77.158.121", Port: 443, Action: "packet_observed", Timestamp: time.Now()})

	violations, _, _ := packetRec.SnapshotAndReset()
	if len(violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(violations))
	}

	if violations[0].Domain != "howett.net" {
		t.Fatalf("domain = %q, want howett.net (shared cache should attribute)", violations[0].Domain)
	}
}

func TestViolationRecorder_Cap(t *testing.T) {
	r := NewViolationRecorder(nil)

	for i := 0; i < maxViolationsPerContainer+100; i++ {
		r.RecordViolation(Violation{Domain: "evil.com", Action: "dns_blocked", Timestamp: time.Now()})
	}

	violations, _ := r.Snapshot()
	if len(violations) != maxViolationsPerContainer {
		t.Fatalf("violations = %d, want %d", len(violations), maxViolationsPerContainer)
	}
}
