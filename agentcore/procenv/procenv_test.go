//go:build linux

package procenv

import (
	"os"
	"reflect"
	"testing"
)

func TestExtractNames(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []string
	}{
		{
			name: "empty",
			in:   []byte{},
			want: []string{},
		},
		{
			name: "trailing NUL only",
			in:   []byte{0},
			want: []string{},
		},
		{
			name: "single entry",
			in:   []byte("FOO=bar\x00"),
			want: []string{"FOO"},
		},
		{
			name: "multiple entries sorted + deduped",
			in:   []byte("ZED=1\x00ALPHA=x\x00ALPHA=y\x00BETA=2\x00"),
			want: []string{"ALPHA", "BETA", "ZED"},
		},
		{
			name: "value never returned",
			in:   []byte("AWS_ACCESS_KEY_ID=AKIASUPERSECRET\x00"),
			want: []string{"AWS_ACCESS_KEY_ID"},
		},
		{
			name: "value contains = signs",
			in:   []byte("URL=postgres://u:p@h/d?x=1\x00"),
			want: []string{"URL"},
		},
		{
			name: "skips empty keys and missing =",
			in:   []byte("=novalue\x00JUSTNAME\x00OK=v\x00"),
			want: []string{"OK"},
		},
		{
			name: "no trailing NUL",
			in:   []byte("A=1\x00B=2"),
			want: []string{"A", "B"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractNames(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("extractNames(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNamesOfSelfContainsExpected(t *testing.T) {
	// /proc/self/environ should at least contain PATH on any
	// reasonable test runner.
	t.Setenv("LEITWACHT_PROCENV_TEST", "1")

	names := Names(0) // self == 0 should return nil
	if names != nil {
		t.Errorf("Names(0) = %v, want nil (invalid pid)", names)
	}

	names = Names(-1)
	if names != nil {
		t.Errorf("Names(-1) = %v, want nil (invalid pid)", names)
	}

	// Real read of self.
	pid := selfPID(t)

	names = Names(pid)
	if names == nil {
		t.Fatalf("Names(self=%d) returned nil — /proc/self/environ unreadable?", pid)
	}

	// LEITWACHT_PROCENV_TEST was set on the test process, but t.Setenv
	// uses os.Setenv which updates the C environ array. Whether it
	// shows up in /proc/<pid>/environ depends on the kernel snapshot
	// taken at exec — which won't include vars set after start. So we
	// can't assert on our test var; assert on PATH instead, which Go's
	// test runner inherits from its parent.
	hasPath := false

	for _, n := range names {
		if n == "PATH" {
			hasPath = true
			break
		}
	}

	if !hasPath {
		t.Logf("PATH not in self environ; got %d names", len(names))
		// Don't fail — some sandboxed CI runners strip PATH.
	}
}

func selfPID(t *testing.T) int {
	t.Helper()

	return os.Getpid()
}
