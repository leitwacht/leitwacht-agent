package main

import "testing"

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"attached version=1.2.3", "1.2.3"},
		{"attached version=v1.2.3 node=foo", "v1.2.3"},
		{"attached", ""},
		{"attached version=", ""},
		{"attached version=1.0.0-rc1 extra=field", "1.0.0-rc1"},
		{"unrelated", ""},
	}

	for _, tc := range cases {
		got := extractVersion(tc.in)
		if got != tc.want {
			t.Errorf("extractVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"v1.2.3", []int{1, 2, 3}},
		{"10.20.30", []int{10, 20, 30}},
		{"1.2.3-rc1", []int{1, 2, 3}},
		{"1.2.3-dirty", []int{1, 2, 3}},
		{"1.2", nil},
		{"dev", nil},
		{"", nil},
		{"1.2.abc", nil},
	}

	for _, tc := range cases {
		got := parseVersion(tc.in)
		if !intSliceEqual(got, tc.want) {
			t.Errorf("parseVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	cases := []struct {
		agent, required string
		wantOK          bool
	}{
		// Agent >= required: pass.
		{"1.2.3", "1.2.3", true},
		{"1.2.4", "1.2.3", true},
		{"2.0.0", "1.99.99", true},
		// Agent < required: fail.
		{"1.2.2", "1.2.3", false},
		{"1.1.99", "1.2.0", false},
		{"0.9.0", "1.0.0", false},
		// Unparseable on either side: pass (don't wedge local-dev).
		{"dev", "1.2.3", true},
		{"1.2.3", "dev", true},
		{"", "", true},
	}

	for _, tc := range cases {
		ok, reason := checkVersion(tc.agent, tc.required)
		if ok != tc.wantOK {
			t.Errorf("checkVersion(%q, %q) ok=%v reason=%q, want ok=%v",
				tc.agent, tc.required, ok, reason, tc.wantOK)
		}
	}
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
