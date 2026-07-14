//go:build linux

package enforcer

import "golang.org/x/sys/unix"

// nowMonotonicNs returns the current CLOCK_MONOTONIC time in nanoseconds — the
// same clock bpf_ktime_get_ns() reads — so it can be paired with a wall-clock
// sample to convert BPF event timestamps (see monotonicToWallNs).
//
// On the near-impossible clock_gettime failure it returns 0, which makes
// monotonicToWallNs treat the event as "now" (delta clamps to zero) rather than
// producing a bogus far-past timestamp.
func nowMonotonicNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}

	return ts.Nano()
}
