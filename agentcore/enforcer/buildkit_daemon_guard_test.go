package enforcer

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const guardCgID = 777

// fakeProc stages /proc/<pid>/{comm,status}.
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

// fakeUnixListener makes daemon pid the owner of a listening unix socket
// at <rootfs>/run/buildkit/buildkitd.sock and returns that file's path.
func fakeUnixListener(t *testing.T, root string, pid int) string {
	t.Helper()

	rootfs := filepath.Join(root, "rootfs", strconv.Itoa(pid))
	sock := filepath.Join(rootfs, "run", "buildkit", "buildkitd.sock")

	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(sock, nil, 0o644); err != nil { //nolint:gosec // fixture
		t.Fatal(err)
	}

	pdir := filepath.Join(root, "proc", strconv.Itoa(pid))
	ino := strconv.Itoa(90000 + pid)

	guardLink(t, rootfs, filepath.Join(pdir, "root"))
	guardWrite(t, filepath.Join(pdir, "net", "unix"),
		"Num RefCount Protocol Flags Type St Inode Path\n"+
			"0000: 00000002 00000000 00010000 0001 01 "+ino+" /run/buildkit/buildkitd.sock\n")
	guardLink(t, "socket:["+ino+"]", filepath.Join(pdir, "fd", "3"))

	return sock
}

// fakeTCPListener makes daemon pid listen on port.
func fakeTCPListener(t *testing.T, root string, pid, port int) {
	t.Helper()

	pdir := filepath.Join(root, "proc", strconv.Itoa(pid))
	ino := strconv.Itoa(80000 + pid)

	guardWrite(t, filepath.Join(pdir, "net", "tcp"),
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			fmt.Sprintf("   0: 00000000:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %s 1 0 0\n", port, ino))
	guardLink(t, "socket:["+ino+"]", filepath.Join(pdir, "fd", "4"))
}

func guardWrite(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // fixture
		t.Fatal(err)
	}
}

func guardLink(t *testing.T, target, link string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

type guardEnv struct {
	t    *testing.T
	root string
	reg  *SessionRegistry
	log  *bytes.Buffer
	j    *CgroupJoiner
}

func newGuardEnv(t *testing.T, addr string, deferred time.Duration) *guardEnv {
	t.Helper()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}

	e := &guardEnv{t: t, root: root, reg: NewSessionRegistry(time.Minute), log: &bytes.Buffer{}}

	e.reg.RegisterSession("rA", time.Unix(1000, 0), map[string]string{
		FrontendAttrKeyProjectPath: "grp/a", FrontendAttrKeyJobID: "1",
	})
	e.reg.UpsertVertex("rA", VertexState{Digest: "dA", Name: "[build 1/2] RUN npm ci", StartedAt: time.Unix(1010, 0)})

	e.j = NewCgroupJoiner(e.reg, newFakeEventSource(), slog.New(slog.NewTextHandler(e.log, nil)),
		WithProcRoot(filepath.Join(root, "proc")),
		WithStatFn(func(string) (uint64, error) { return guardCgID, nil }),
		WithDeferredMatch(deferred, 10*time.Millisecond),
		WithDaemonGuard(addr),
	)

	return e
}

// runUnder stages a RUN cgroup (process 5000 under runc 4000, whose parent
// is parent; parent<0 leaves runc missing so the walk fails mid-way).
func (e *guardEnv) runUnder(parent int) CgroupCreateEvent {
	e.t.Helper()

	fakeProc(e.t, e.root, 5000, 4000, "sh")

	if parent >= 0 {
		fakeProc(e.t, e.root, 4000, parent, "runc")
	}

	cg := stageCgroup(e.t, e.root, "ctr-guard", 5000, "/bin/sh\x00-c\x00npm ci\x00")

	return CgroupCreateEvent{ContainerID: "ctr-guard", CgroupPath: cg}
}

func (e *guardEnv) join(evt CgroupCreateEvent) (CgroupBinding, bool) {
	e.t.Helper()

	e.j.handleCreate(context.Background(), evt)

	return e.reg.LookupByCgroupID(guardCgID)
}

func assertLinkedB(t *testing.T, b CgroupBinding) {
	t.Helper()
	assertLinked(t, b, b.Flag != "missing")
}

func assertLinked(t *testing.T, b CgroupBinding, ok bool) {
	t.Helper()

	if !ok || b.SessionRef != "rA" || b.VertexDigest != "dA" || b.Flag != "" {
		t.Fatalf("binding = %+v ok=%v, want normal exact link", b, ok)
	}
}

func assertBlocked(t *testing.T, b CgroupBinding, ok bool, flag string) {
	t.Helper()

	if !ok {
		t.Fatal("expected an unattributed binding")
	}

	if b.Flag != flag || b.VertexDigest != "" || b.SessionRef != "" || b.Ambiguous || len(b.CandidateKeys) != 0 {
		t.Fatalf("binding = %+v, want flag %s with no vertex/session/candidates", b, flag)
	}

	v := Violation{CgroupID: guardCgID, Timestamp: time.Unix(1020, 0), EnforcementState: EnfStatePendingBind}
	applyBuildKitBinding(&v, b)

	sess := []SessionState{{
		Ref: "rA", StartedAt: time.Unix(1000, 0),
		FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: "grp/a", FrontendAttrKeyJobID: "1"},
	}}
	vs := []Violation{v}
	attributeBySession(vs, func(time.Time) ([]SessionState, bool) { return sess, true })
	markUnattributed(vs)
	FinalizeUnbound(vs)

	if vs[0].BuildSessionRef != "" || vs[0].BuildProjectPath != "" || vs[0].BuildFlag != flag {
		t.Fatalf("row was attributed: %+v", vs[0])
	}

	if !vs[0].BuildUnattributed || vs[0].BuildAmbiguous || vs[0].EnforcementState != EnfStateUnattributed {
		t.Fatalf("row not filed unattributed: %+v", vs[0])
	}

	if out := classify(b); out.state != bkStateUnattributed {
		t.Fatalf("classify state = %d, want unattributed", out.state)
	}
}

func TestDaemonGuard_UnixSocketWatchedLinksAndForeignBlocked(t *testing.T) {
	e := newGuardEnv(t, "tcp://x:1", 0) // replaced below once the socket exists
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	sock := fakeUnixListener(t, e.root, 3000)
	fakeUnixListener(t, e.root, 3100)

	e.j.guard.addr = "unix://" + sock

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	e2 := newGuardEnv(t, "tcp://x:1", 0)
	fakeProc(t, e2.root, 3000, 1, "buildkitd")
	fakeProc(t, e2.root, 3100, 1, "buildkitd")
	sock2 := fakeUnixListener(t, e2.root, 3000)
	fakeUnixListener(t, e2.root, 3100)
	e2.j.guard.addr = "unix://" + sock2

	b, ok := e2.join(e2.runUnder(3100))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)

	if !strings.Contains(e2.log.String(), "several buildkitd processes") {
		t.Fatalf("expected the multi-daemon Error log:\n%s", e2.log.String())
	}
}

func TestDaemonGuard_TCPSingleLocalUnrelatedDaemonDoesNotTakeOver(t *testing.T) {
	e := newGuardEnv(t, "tcp://buildkitd.ns.svc:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	e2 := newGuardEnv(t, "tcp://buildkitd.ns.svc:1234", 0)
	fakeProc(t, e2.root, 3000, 1, "buildkitd")
	fakeProc(t, e2.root, 3100, 1, "buildkitd")
	fakeTCPListener(t, e2.root, 3000, 1234)

	b, ok := e2.join(e2.runUnder(3100))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func guardBinding(b CgroupBinding, ok bool) CgroupBinding {
	if !ok {
		return CgroupBinding{Flag: "missing"}
	}

	return b
}

func TestDaemonGuard_RemoteWatchedDaemonLocalOneIsForeign(t *testing.T) {
	// The watched daemon is remote; the only local buildkitd is unrelated.
	e := newGuardEnv(t, "tcp://remote.example:1234", 0)
	fakeProc(t, e.root, 3100, 1, "buildkitd")

	b, ok := e.join(e.runUnder(3100))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)

	if !strings.Contains(e.log.String(), "no local buildkitd listens on the watched address") {
		t.Fatalf("expected the tie Error log:\n%s", e.log.String())
	}
}

func TestDaemonGuard_RemoteWatchedUnresolvedOwnerUnverified(t *testing.T) {
	e := newGuardEnv(t, "tcp://remote.example:1234", 0)
	fakeProc(t, e.root, 3100, 1, "buildkitd")

	// Ancestry reaches init without a buildkitd (e.g. containerd worker).
	b, ok := e.join(e.runUnder(1))
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)
}

func TestDaemonGuard_SeveralMatchingDaemons(t *testing.T) {
	// Host network: two daemons both appear to listen on the port.
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeProc(t, e.root, 3200, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)
	fakeTCPListener(t, e.root, 3100, 1234)

	b, ok := e.join(e.runUnder(3000))
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)

	e2 := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e2.root, 3000, 1, "buildkitd")
	fakeProc(t, e2.root, 3100, 1, "buildkitd")
	fakeProc(t, e2.root, 3200, 1, "buildkitd")
	fakeTCPListener(t, e2.root, 3000, 1234)
	fakeTCPListener(t, e2.root, 3100, 1234)

	b, ok = e2.join(e2.runUnder(3200))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_ZeroDaemonsUnchangedWarnOnce(t *testing.T) {
	e := newGuardEnv(t, "tcp://remote:1234", 0)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(0))))
	_, _ = e.j.guard.snapshot(true)
	time.Sleep(1100 * time.Millisecond) // forced rescans are rate limited
	_, _ = e.j.guard.snapshot(true)

	if n := strings.Count(e.log.String(), "cannot verify which buildkitd"); n != 1 {
		t.Fatalf("warn count = %d, want 1:\n%s", n, e.log.String())
	}
}

func TestDaemonGuard_OnlyWatchedVisibleUnresolvedOwnerUnchanged(t *testing.T) {
	// containerd worker shape: only the watched daemon is visible and the
	// process tree does not lead to it. Today's behaviour is kept.
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(1))))

	if !strings.Contains(e.log.String(), "requires the OCI (runc) worker") {
		t.Fatalf("expected the worker warning:\n%s", e.log.String())
	}
}

func TestDaemonGuard_SpoofedSecondDaemonDoesNotDowngradeWatched(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)
	// A CI job process renames itself buildkitd.
	fakeProc(t, e.root, 3300, 1, "buildkitd")

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))
}

func TestDaemonGuard_SpoofedNameInsideRunStepResolvesOutermost(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 3000, 1, "buildkitd")
	fakeProc(t, root, 4000, 3000, "runc")
	fakeProc(t, root, 5000, 4000, "buildkitd") // RUN process renamed itself

	pid, found, def := ancestorDaemon(filepath.Join(root, "proc"), 5000)
	if !found || pid != 3000 || !def {
		t.Fatalf("got %d,%v,%v want 3000,true,true", pid, found, def)
	}
}

func TestDaemonGuard_NestedDaemonInJobIsForeign(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)
	fakeProc(t, e.root, 2000, 1, "sh") // CI job shell
	fakeProc(t, e.root, 3400, 2000, "buildkitd")

	b, ok := e.join(e.runUnder(3400))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_DaemonRestartReties(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	// The daemon restarts under a new pid within the cache window.
	if err := os.RemoveAll(filepath.Join(e.root, "proc", "3000")); err != nil {
		t.Fatal(err)
	}

	fakeProc(t, e.root, 3500, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3500, 1234)

	e.reg.UnlinkCgroup(guardCgID)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3500))))
}

func TestDaemonGuard_RetryResolvesOwnerLater(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 2*time.Second)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e.j.handleCreate(ctx, e.runUnder(-1)) // runc not yet in /proc: walk fails mid-way

	go func() {
		time.Sleep(60 * time.Millisecond)
		fakeProc(t, e.root, 4000, 3000, "runc")
	}()

	waitFor(t, time.Second, func() bool {
		_, ok := e.reg.LookupByCgroupID(guardCgID)

		return ok
	})

	b, _ := e.reg.LookupByCgroupID(guardCgID)
	assertLinked(t, b, true)
}

func TestDaemonGuard_DefinitiveFailureLinksImmediately(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 5*time.Second)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	start := time.Now()
	b, ok := e.join(e.runUnder(1)) // walk completes at init: not found

	if time.Since(start) > time.Second {
		t.Fatal("blocked binding waited for the deadline")
	}

	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)
}

func TestDaemonGuard_RemovedBeforeResolvedIsUnverified(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 2*time.Second)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	cg := filepath.Join(e.root, "cgroups", "ctr-guard")
	guardWrite(t, filepath.Join(cg, "cgroup.procs"), "") // empty: nothing readable

	source := newFakeEventSource()
	e.j.source = source

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})

	go func() {
		_ = e.j.Run(ctx)

		close(done)
	}()

	evt := CgroupCreateEvent{ContainerID: "ctr-guard", CgroupPath: cg}
	source.creates <- evt

	time.Sleep(50 * time.Millisecond)

	source.removes <- CgroupRemoveEvent{ContainerID: "ctr-guard", CgroupPath: cg}

	waitFor(t, time.Second, func() bool {
		b, ok := e.reg.LookupForEvent(guardCgID, time.Now())

		return ok && b.Flag == BuildFlagDaemonUnverified
	})

	cancel()
	<-done
}

func TestAncestorDaemon(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 10, 1, "buildkitd")
	fakeProc(t, root, 11, 10, "runc")
	fakeProc(t, root, 12, 11, "sh")
	fakeProc(t, root, 20, 21, "a") // cycle
	fakeProc(t, root, 21, 20, "b")

	pr := filepath.Join(root, "proc")

	if pid, ok, def := ancestorDaemon(pr, 12); !ok || pid != 10 || !def {
		t.Fatalf("got %d,%v,%v want 10,true,true", pid, ok, def)
	}

	if _, ok, def := ancestorDaemon(pr, 20); ok || def {
		t.Fatal("cycle must not resolve definitively")
	}

	if _, ok, def := ancestorDaemon(pr, 999); ok || def {
		t.Fatal("missing pid must not resolve definitively")
	}
}
