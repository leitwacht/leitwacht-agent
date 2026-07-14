package enforcer

import (
	"testing"
	"time"
)

// TestMonotonicToWallNs_RegressionNot1970 is the regression guard for the LSM
// timestamp bug: BPF stamps events with bpf_ktime_get_ns() (CLOCK_MONOTONIC —
// nanoseconds since boot), which fed straight into time.Unix(0, ns) landed the
// server's last_seen near 1970-01-01, so ClickHouse TTL-purged the row on
// ingest while the security alert (independent of last_seen) still fired.
// A boot-relative event time must convert to ~now, never ~1970.
func TestMonotonicToWallNs_RegressionNot1970(t *testing.T) {
	nowWall := time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC).UnixNano()
	nowMono := int64(1000 * time.Second)     // 1000s of uptime
	eventMono := int64(5 * time.Millisecond) // event stamped ~5ms after boot

	got := monotonicToWallNs(eventMono, nowMono, nowWall)
	gotT := time.Unix(0, got).UTC()

	if gotT.Year() < 2020 {
		t.Fatalf("converted timestamp is %s (year %d); the 1970 TTL bug is back", gotT, gotT.Year())
	}

	// The event happened (nowMono-eventMono) before nowWall.
	wantDelta := nowMono - eventMono
	if gotDelta := nowWall - got; gotDelta != wantDelta {
		t.Fatalf("back-dated by %d ns, want %d ns", gotDelta, wantDelta)
	}
}

// TestMonotonicToWallNs_Fresh: an event stamped at the same instant we sampled
// the clocks maps to exactly now.
func TestMonotonicToWallNs_Fresh(t *testing.T) {
	nowWall := int64(1_752_480_000_000_000_000)
	nowMono := int64(1000 * time.Second)

	if got := monotonicToWallNs(nowMono, nowMono, nowWall); got != nowWall {
		t.Fatalf("fresh event mapped to %d, want %d", got, nowWall)
	}
}

// TestMonotonicToWallNs_NoPostDating: a small sampling race can leave the event
// monotonic value slightly ahead of our sampled monotonic clock. We must clamp
// to "now" rather than post-date the event into the future.
func TestMonotonicToWallNs_NoPostDating(t *testing.T) {
	nowWall := int64(1_752_480_000_000_000_000)
	nowMono := int64(1000 * time.Second)
	eventMono := nowMono + int64(2*time.Millisecond) // 2ms "in the future"

	if got := monotonicToWallNs(eventMono, nowMono, nowWall); got != nowWall {
		t.Fatalf("future-skewed event mapped to %d, want clamped to %d", got, nowWall)
	}
}
