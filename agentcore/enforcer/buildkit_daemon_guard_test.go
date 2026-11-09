package enforcer

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProc stages /proc/<pid>/{comm,status} entries under root/proc.
func fakeProc(t *testing.T, root string, pid, ppid int, comm string) {
	t.Helper()

	dir := filepath.Join(root, "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	status := "Name:\t" + comm + "\nPPid:\t" + strconv.Itoa(ppid) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil { //nolint:gosec // fixture
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil { //nolint:gosec // fixture
		t.Fatal(err)
	}
}

// guardRun stages a RUN cgroup (pid 5000, under runc 4000) whose runc
// parent is parentDaemon (0: orphaned, ancestry unresolvable) and joins it.
func guardRun(t *testing.T, root string, reg *SessionRegistry, grpcAddr string, parentDaemon int, logBuf *bytes.Buffer) (CgroupBinding, bool) {
	t.Helper()

	reg.RegisterSession("rA", time.Unix(1000, 0), map[string]string{
		FrontendAttrKeyProjectPath: "grp/a", FrontendAttrKeyJobID: "1",
	})
	reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: "[build 1/2] RUN npm ci", StartedAt: time.Unix(1010, 0)})

	fakeProc(t, root, 5000, 4000, "sh")
	fakeProc(t, root, 4000, parentDaemon, "runc")

	cg := stageCgroup(t, root, "ctr-guard", 5000, "/bin/sh\x00-c\x00npm ci\x00")
	if err := os.WriteFile(filepath.Join(root, "proc", "5000", "cmdline"), []byte("/bin/sh\x00-c\x00npm ci\x00"), 0o644); err != nil { //nolint:gosec // fixture
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	j := NewCgroupJoiner(reg, newFakeEventSource(), logger,
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(func(string) (uint64, error) { return 777, nil }),
		WithDeferredMatch(0, 0),
		WithDaemonGuard(grpcAddr),
	)

	j.handleCreate(context.Background(), CgroupCreateEvent{ContainerID: "ctr-guard", CgroupPath: cg})
	// Re-scan: the no-daemon warning must still be logged only once.
	_ = j.guard.discover(true)

	return reg.LookupByCgroupID(777)
}

func assertBlocked(t *testing.T, b CgroupBinding, ok bool, flag string) {
	t.Helper()

	if !ok {
		t.Fatal("expected an (unattributed) binding")
	}

	if b.Flag != flag || b.VertexDigest != "" || b.SessionRef != "" || len(b.CandidateKeys) != 0 {
		t.Fatalf("binding = %+v, want flag %s with no vertex/session/candidates", b, flag)
	}

	// Session-level fallback must not attribute it either.
	v := Violation{CgroupID: 777, Timestamp: time.Unix(1020, 0)}
	applyBuildKitBinding(&v, b)

	sess := []SessionState{{
		Ref: "rA", StartedAt: time.Unix(1000, 0),
		FrontendAttrs: map[string]string{
			FrontendAttrKeyProjectPath: "grp/a", FrontendAttrKeyJobID: "1",
		},
	}}
	vs := []Violation{v}
	attributeBySession(vs, func(time.Time) ([]SessionState, bool) { return sess, true })

	if vs[0].BuildSessionRef != "" || vs[0].BuildProjectPath != "" || vs[0].BuildFlag != flag {
		t.Fatalf("row was attributed: %+v", vs[0])
	}

	if out := classify(b); out.state != bkStateUnattributed {
		t.Fatalf("classify state = %d, want unattributed", out.state)
	}
}

func TestDaemonGuard_SingleDaemonUnchanged(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd")

	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "tcp://buildkitd:1234", 3000, &buf)
	if !ok || b.SessionRef != "rA" || b.VertexDigest != "dA" || b.Flag != "" {
		t.Fatalf("binding = %+v ok=%v, want normal exact link", b, ok)
	}
}

func TestDaemonGuard_ZeroDaemonsUnchangedWarnOnce(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "tcp://remote:1234", 0, &buf)
	if !ok || b.VertexDigest != "dA" || b.Flag != "" {
		t.Fatalf("binding = %+v ok=%v, want normal exact link", b, ok)
	}

	if n := strings.Count(buf.String(), "cannot verify which buildkitd"); n != 1 {
		t.Fatalf("warn count = %d, want 1:\n%s", n, buf.String())
	}
}

func TestDaemonGuard_ForeignDaemonPinned(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd") // watched
	fakeProc(t, root, 3100, 1, "buildkitd") // foreign

	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "unix:///proc/3000/root/run/buildkit/buildkitd.sock", 3100, &buf)
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_PinnedWatchedDaemonLinks(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd")
	fakeProc(t, root, 3100, 1, "buildkitd")

	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "unix:///proc/3000/root/run/buildkit/buildkitd.sock", 3000, &buf)
	if !ok || b.VertexDigest != "dA" || b.Flag != "" {
		t.Fatalf("binding = %+v ok=%v, want normal exact link", b, ok)
	}
}

func TestDaemonGuard_PinnedUnresolvableIsUnverified(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd")

	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "unix:///proc/3000/root/x.sock", 0, &buf)
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)
}

func TestDaemonGuard_TwoDaemonsUnpinnedUnverified(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd")
	fakeProc(t, root, 3100, 1, "buildkitd")

	// Even a RUN whose owner is resolvable cannot be proven to be the
	// watched daemon's.
	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "tcp://buildkitd:1234", 3000, &buf)
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)
}

func TestDaemonGuard_TwoDaemonsUnresolvableAncestry(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd")
	fakeProc(t, root, 3100, 1, "buildkitd")

	var buf bytes.Buffer

	b, ok := guardRun(t, root, NewSessionRegistry(time.Minute), "tcp://buildkitd:1234", 0, &buf)
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)
}

func TestAncestorDaemon(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 10, 1, "buildkitd")
	fakeProc(t, root, 11, 10, "runc")
	fakeProc(t, root, 12, 11, "sh")
	fakeProc(t, root, 20, 21, "a") // cycle
	fakeProc(t, root, 21, 20, "b")

	pr := filepath.Join(root, "proc")

	if pid, ok := ancestorDaemon(pr, 12); !ok || pid != 10 {
		t.Fatalf("got %d,%v want 10,true", pid, ok)
	}

	if _, ok := ancestorDaemon(pr, 20); ok {
		t.Fatal("cycle must not resolve")
	}

	if _, ok := ancestorDaemon(pr, 999); ok {
		t.Fatal("missing pid must not resolve")
	}
}
