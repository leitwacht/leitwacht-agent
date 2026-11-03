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

	if !got[0].ObserveOnly {
		t.Error("ReportOnly events must also set ObserveOnly (defence in depth)")
	}

	if got[1].ReportOnly || got[1].ObserveOnly {
		t.Errorf("plain event must not be ReportOnly: %+v", got[1])
	}
}

func pairKeyOf(parent, name string) [96]byte {
	var k [96]byte
	copy(k[:31], parent)
	copy(k[32:95], name)

	return k
}

func TestBuildWatchClasses(t *testing.T) {
	// A suffix in both lists is report-only.
	wc := buildWatchClasses([]string{"/.docker/config.json", "/.aws/credentials"}, []string{"/.docker/config.json"}, nil)
	if got := wc.pairs[pairKeyOf(".docker", "config.json")]; got != credwatchClassReportOnly {
		t.Errorf("shared suffix pair class = %d, want report-only", got)
	}

	// Exclude beats both.
	wc = buildWatchClasses([]string{"/.aws/credentials"}, []string{"/.npmrc"}, []string{"/.aws/credentials", "/.npmrc"})
	if len(wc.suffixes) != 0 || len(wc.pairs) != 0 || len(wc.dirs) != 0 {
		t.Errorf("excluded suffixes must not be inserted: %+v", wc)
	}

	// Finding 2: report-only never downgrades a pair/dir key a different
	// watched suffix holds, in either list order.
	wc = buildWatchClasses([]string{"/x/.docker/config.json"}, []string{"/.docker/config.json"}, nil)
	if got := wc.pairs[pairKeyOf(".docker", "config.json")]; got != credwatchClassWatched {
		t.Errorf("pair downgraded to %d", got)
	}

	if got := wc.dirs[pairKeyOf("x", ".docker")]; got != credwatchClassWatched {
		t.Errorf("dir (x,.docker) class = %d, want watched", got)
	}

	// The report-only suffix itself keeps its own class.
	var sk [64]byte
	copy(sk[:], "/.docker/config.json")

	if got := wc.suffixes[sk]; got != credwatchClassReportOnly {
		t.Errorf("suffix class = %d, want report-only", got)
	}

	// Finding 3: a report-only file registers its parent dir as class 2.
	wc = buildWatchClasses(nil, []string{"/.docker/config.json"}, nil)
	if got := wc.dirs[pairKeyOf("", ".docker")]; got != credwatchClassReportOnly {
		t.Errorf("report-only parent dir class = %d, want report-only", got)
	}

	// Finding 1 (userspace half): a name-only report-only entry has an
	// empty parent, so it is a different key from the exact watched pair.
	wc = buildWatchClasses([]string{"/.aws/credentials"}, []string{"/credentials"}, nil)
	if wc.pairs[pairKeyOf(".aws", "credentials")] != credwatchClassWatched ||
		wc.pairs[pairKeyOf("", "credentials")] != credwatchClassReportOnly {
		t.Errorf("exact and name-only pairs must keep separate classes: %+v", wc.pairs)
	}
}
