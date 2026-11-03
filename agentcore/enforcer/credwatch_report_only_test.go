//go:build linux

package enforcer

import "testing"

func TestCredwatchKindReportOnly(t *testing.T) {
	cases := []struct {
		kind   uint8
		reason string
		ro     bool
	}{
		{credwatchKindOpen, "open", false},
		{credwatchKindRename, "rename", false},
		{credwatchKindLink, "link", false},
		{credwatchKindDPathFail, "dpath_fail", false},
		{credwatchKindOpen | credwatchKindReportOnly, "open", true},
		{credwatchKindRename | credwatchKindReportOnly, "rename", true},
		{credwatchKindLink | credwatchKindReportOnly, "link", true},
		{credwatchKindDPathFail | credwatchKindReportOnly, "dpath_fail", true},
	}

	for _, tc := range cases {
		if got := credwatchReason(tc.kind); got != tc.reason {
			t.Errorf("credwatchReason(%#x) = %q, want %q", tc.kind, got, tc.reason)
		}

		if got := credwatchKindReportOnlyFlag(tc.kind); got != tc.ro {
			t.Errorf("credwatchKindReportOnlyFlag(%#x) = %v, want %v", tc.kind, got, tc.ro)
		}
	}
}

// TestHandleCredwatchBPFEventReportOnly checks the userspace decode: a
// report-only kind byte surfaces as ReportOnly with the plain reason.
func TestHandleCredwatchBPFEventReportOnly(t *testing.T) {
	mgr := NewManager(testLogger(), 1, nil, nil, nil, CredwatchConfig{}, ProcMemConfig{})

	var got []CredwatchEvent

	mgr.OnCredwatchEvent = func(e CredwatchEvent) { got = append(got, e) }

	evt := credwatchEventBPF{CgroupID: 7, PID: 42, Kind: credwatchKindOpen | credwatchKindReportOnly}
	copy(evt.Path[:], "/root/.docker/config.json")
	mgr.handleCredwatchBPFEvent(evt)

	evt.Kind = credwatchKindOpen
	mgr.handleCredwatchBPFEvent(evt)

	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}

	if !got[0].ReportOnly || got[0].Reason != "open" || got[0].Path != "/root/.docker/config.json" {
		t.Errorf("report-only event decoded wrong: %+v", got[0])
	}

	if got[1].ReportOnly {
		t.Errorf("plain event must not be ReportOnly: %+v", got[1])
	}
}
