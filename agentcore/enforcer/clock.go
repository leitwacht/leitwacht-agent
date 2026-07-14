package enforcer

// monotonicToWallNs converts a CLOCK_MONOTONIC nanosecond timestamp — as
// emitted by bpf_ktime_get_ns() in the LSM programs — into a wall-clock
// epoch-nanosecond timestamp.
//
// BPF stamps events with bpf_ktime_get_ns(), which is nanoseconds since boot
// (CLOCK_MONOTONIC), NOT since the Unix epoch. Feeding that raw value into
// time.Unix(0, ns) on the server yielded a last_seen near 1970-01-01, and the
// violations table's `TTL last_seen + INTERVAL 90 DAY` then purged the row on
// the next merge — while the security alert, which never touches last_seen,
// still fired. Egress rows escaped this because they carry a wall-clock
// time.Now() instead of the BPF clock.
//
// We convert at the userspace boundary (once per event) so every downstream
// consumer — CE sinks and the EE reporter alike — sees a real epoch. nowMonoNs
// and nowWallNs must be sampled at (approximately) the same instant: the event
// happened (nowMonoNs - eventMonoNs) before now, so we back-date nowWallNs by
// that delta. Computing the delta per event (rather than caching a boot epoch)
// keeps us robust to NTP slew over the agent's lifetime.
//
// If eventMonoNs is ahead of nowMonoNs — a small sampling race, or a zeroed
// nowMonoNs from a failed clock read — the delta is clamped to zero so we
// never post-date the event into the future.
func monotonicToWallNs(eventMonoNs, nowMonoNs, nowWallNs int64) int64 {
	delta := nowMonoNs - eventMonoNs
	if delta < 0 {
		delta = 0
	}

	return nowWallNs - delta
}
