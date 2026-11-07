package enforcer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A compound RUN's shell exec-replaces itself with the last simple
// command, so a cgroup sampled after the earlier steps ran shows only
// that command's argv (observed live: argv "sleep 3" for a RUN ending
// "... && sleep 3"). The join must still attribute it.
func TestMatchPendingByArgv_ExecReplacedLastCommand(t *testing.T) {
	canary := `[2/2] RUN echo "nonce 401" && (wget -q -T 5 -O /dev/null http://example.com/ ; echo "wget rc=$?") && sleep 3`
	pending := []PendingVertex{
		{SessionRef: "rA", VertexDigest: "dA", VertexName: canary},
		{SessionRef: "rB", VertexDigest: "dB", VertexName: "[1/1] RUN npm ci"},
	}

	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"exec-replaced last command", []string{"sleep", "3"}, 1},
		{"full shell still matches", []string{"/bin/sh", "-c", `echo "nonce 401" && (wget -q -T 5 -O /dev/null http://example.com/ ; echo "wget rc=$?") && sleep 3`}, 1},
		{"different last command", []string{"sleep", "4"}, 0},
		{"unrelated", []string{"npm", "install"}, 0},
	}

	for _, tc := range cases {
		got := matchPendingByArgv(pending, tc.argv)
		if len(got) == 0 {
			got = matchPendingByTail(pending, tc.argv)
		}

		if len(got) != tc.want {
			t.Errorf("%s: got %d matches (%+v), want %d", tc.name, len(got), got, tc.want)
		}
	}
}

func TestLastSimpleCommand(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		ok   bool
	}{
		{"a && b -x 1", []string{"b", "-x", "1"}, true},
		{`apt-get update && apt-get install -y "curl"`, []string{"apt-get", "install", "-y", "curl"}, true},
		{"x ; (y; z) && w 2>&1", []string{"w"}, true},
		{"cmd > /dev/null", []string{"cmd"}, true},
		{"a | b", []string{"b"}, true},
		{"a && echo $HOME", nil, false},
		{"a && echo `id`", nil, false},
		{"a && rm *.o", nil, false},
		{"a && b 'unterminated", nil, false},
		{"a && (b", nil, false},
		{"", nil, false},
	}

	for _, tc := range cases {
		got, ok := lastSimpleCommand(tc.in)
		if ok != tc.ok || len(got) != len(tc.want) {
			t.Errorf("lastSimpleCommand(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)

			continue
		}

		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("lastSimpleCommand(%q) = %q want %q", tc.in, got, tc.want)

				break
			}
		}
	}
}

// Tiering: an exact match must not be diluted by a weak last-command
// match from another session.
func TestMatchPendingByArgv_ExactBeatsTail(t *testing.T) {
	pending := []PendingVertex{
		{SessionRef: "rB", VertexDigest: "dB", VertexName: "[1/1] RUN make"},
		{SessionRef: "rA", VertexDigest: "dA", VertexName: "[1/1] RUN cd x && make"},
	}

	argv := []string{"/bin/sh", "-c", "make"}

	got := matchPendingByArgv(pending, argv)
	if len(got) != 1 || got[0].SessionRef != "rB" {
		t.Fatalf("exact tier = %+v, want only rB", got)
	}

	// Exec-replaced `make` argv: exact tier empty (argv is not `-c make`
	// and tail of `RUN make` matches rB in the loose tier); A is weak only.
	got = matchPendingByArgv(pending, []string{"make"})
	if len(got) != 1 || got[0].SessionRef != "rB" {
		t.Fatalf("loose tier = %+v, want only rB", got)
	}

	// Only the weak tier knows A.
	if w := matchPendingByTail(pending[1:], []string{"make"}); len(w) != 1 {
		t.Fatalf("tail tier = %+v, want A", w)
	}
}

func TestTailMatchRejectsShellScripts(t *testing.T) {
	// base-name compare must not apply to a whole script argument.
	argv := []string{"sh", "-c", "cd x && cp a /usr/bin/make"}

	if tailMatchesCommand(argv, "make") {
		t.Error("tailMatchesCommand matched a -c script")
	}

	if lastSimpleCommandMatches(argv, "cd x && make") {
		t.Error("lastSimpleCommandMatches matched a -c script")
	}

	if lastSimpleCommandMatches([]string{"/bin/sh -c x/make"}, "a && make") {
		t.Error("matched argv word containing whitespace")
	}
}

func TestLastSimpleCommand_QuotingAndBailouts(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		ok   bool
	}{
		{`echo ">" foo`, []string{"echo", ">", "foo"}, true},
		{`a && echo '<' x`, []string{"echo", "<", "x"}, true},
		{"cat <<EOF > /x", nil, false},
		{"a && b # c", nil, false},
		{"a && cmd hi>/dev/null", nil, false},
		{"a && cmd hi 2>/dev/null", []string{"cmd", "hi"}, true},
		{"a && cmd >f x", []string{"cmd", "x"}, true},
	}

	for _, tc := range cases {
		got, ok := lastSimpleCommand(tc.in)
		if ok != tc.ok || len(got) != len(tc.want) {
			t.Errorf("lastSimpleCommand(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)

			continue
		}

		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("lastSimpleCommand(%q) = %q want %q", tc.in, got, tc.want)

				break
			}
		}
	}
}

// runWeakJoin stages a cgroup whose argv is the exec-replaced `sleep 3`
// of a compound RUN and returns the resulting binding.
func runWeakJoin(t *testing.T, sessions map[string]map[string]string, environ string) CgroupBinding {
	t.Helper()

	root := t.TempDir()
	reg := NewSessionRegistry(time.Minute)

	for ref, attrs := range sessions {
		reg.RegisterSession(ref, time.Unix(1000, 0), attrs)
		reg.UpsertVertex(ref, VertexState{
			Digest:    "d-" + ref,
			Name:      "[2/2] RUN echo hi && sleep 3",
			StartedAt: time.Unix(1010, 0),
		})
	}

	cgroupPath := stageCgroup(t, root, "ctr-weak", 4343, "sleep\x003\x00")

	if environ != "" {
		envPath := filepath.Join(root, "proc", "4343", "environ")
		if err := os.WriteFile(envPath, []byte(environ), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}

	source := newFakeEventSource()
	j := NewCgroupJoiner(reg, source, nil,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(func(string) (uint64, error) { return 5555, nil }),
		WithDeferredMatch(150*time.Millisecond, 20*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = j.Run(ctx) }()

	source.creates <- CgroupCreateEvent{ContainerID: "ctr-weak", CgroupPath: cgroupPath}

	waitFor(t, 2*time.Second, func() bool {
		_, ok := reg.LookupByCgroupID(5555)

		return ok
	})

	b, _ := reg.LookupByCgroupID(5555)

	return b
}

func TestCgroupJoiner_WeakMatchNeverSingleLinkedWithoutEnviron(t *testing.T) {
	attrs := map[string]string{"build-arg:LEITWACHT_CI_JOB_ID": "7"}

	b := runWeakJoin(t, map[string]map[string]string{"rA": attrs}, "")
	if !b.Ambiguous || len(b.AmbiguousCandidates) != 1 {
		t.Fatalf("weak match without environ must be ambiguous, got %+v", b)
	}
}

func TestCgroupJoiner_WeakMatchEnvironNeverSingleLinks(t *testing.T) {
	sessions := map[string]map[string]string{
		"rA": {"build-arg:LEITWACHT_CI_JOB_ID": "7"},
		"rB": {"build-arg:LEITWACHT_CI_JOB_ID": "8"},
	}

	// Even an environ that "confirms" rB must stay ambiguous: environ is
	// controlled by the RUN.
	b := runWeakJoin(t, sessions, "PATH=/bin\x00LEITWACHT_CI_JOB_ID=8\x00")
	if !b.Ambiguous || len(b.AmbiguousCandidates) != 2 {
		t.Fatalf("weak match must bind ambiguous over both, got %+v", b)
	}
}

func TestTailMatch_DashCIsOrdinaryFlag(t *testing.T) {
	pending := []PendingVertex{{SessionRef: "rA", VertexName: "[1/1] RUN gcc -c x.c"}}
	if got := matchPendingByArgv(pending, []string{"gcc", "-c", "x.c"}); len(got) != 1 {
		t.Fatalf("gcc -c x.c: got %+v", got)
	}

	pending = []PendingVertex{{SessionRef: "rA", VertexName: "[1/1] RUN cd x && git -c k=v status"}}
	if got := matchPendingByTail(pending, []string{"git", "-c", "k=v", "status"}); len(got) != 1 {
		t.Fatalf("git -c k=v status: got %+v", got)
	}
}
