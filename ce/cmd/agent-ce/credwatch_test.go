package main

import (
	"testing"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

func TestCredwatchAction(t *testing.T) {
	cases := []struct {
		name string
		ev   enforcer.CredwatchEvent
		want string
	}{
		{"deny in enforce", enforcer.CredwatchEvent{}, "killed"},
		{"observe mode", enforcer.CredwatchEvent{ObserveOnly: true}, "observed"},
		{"report-only path", enforcer.CredwatchEvent{ReportOnly: true}, "reported"},
		{"report-only path in observe mode", enforcer.CredwatchEvent{ReportOnly: true, ObserveOnly: true}, "reported"},
	}

	for _, tc := range cases {
		if got := credwatchAction(tc.ev); got != tc.want {
			t.Errorf("%s: action = %q, want %q", tc.name, got, tc.want)
		}
	}
}
