//go:build linux

package enforcer

import "testing"

func TestActionForDrop(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		reason    uint8
		auditMode bool
		want      string
	}{
		{"block/policy", dropReasonPolicy, false, "packet_dropped"},
		{"block/sinkhole", dropReasonSinkhole, false, "sinkhole_hit"},
		{"audit/policy", dropReasonPolicy, true, "packet_observed"},
		{"audit/sinkhole", dropReasonSinkhole, true, "packet_observed"},
		{"block/unknown", 99, false, "packet_dropped"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := actionForDrop(tc.reason, tc.auditMode)
			if got != tc.want {
				t.Errorf("actionForDrop(%d, audit=%v) = %q, want %q",
					tc.reason, tc.auditMode, got, tc.want)
			}
		})
	}
}
