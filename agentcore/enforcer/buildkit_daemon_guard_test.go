package enforcer

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
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

// fakeWatchedTCP makes pid listen on port AND hold the server end of the
// agent's connection (the default tracked peer 10.1.1.5:40000).
func fakeWatchedTCP(t *testing.T, root string, pid, port int) {
	t.Helper()

	fakeTCPListener(t, root, pid, port)

	f := filepath.Join(root, "proc", strconv.Itoa(pid), "net", "tcp")
	b, _ := os.ReadFile(f)
	ino := strconv.Itoa(70000 + pid)

	guardWrite(t, f, string(b)+"   1: 0A01010A:04D2 "+procAddr(net.ParseIP("10.1.1.5"), 40000, false)+
		" 01 00000000:00000000 00:00000000 00000000     0        0 "+ino+" 1 0 0\n")
	guardLink(t, "socket:["+ino+"]", filepath.Join(root, "proc", strconv.Itoa(pid), "fd", "5"))
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
	clk  atomic.Int64 // guard clock, unix nanos
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

	if strings.HasPrefix(addr, "tcp:") {
		tr := NewBuildKitConnTracker()
		tr.set(&net.TCPAddr{IP: net.ParseIP("10.1.1.5"), Port: 40000}, &net.TCPAddr{IP: net.ParseIP("10.1.1.10"), Port: 1234})
		e.j.guard.tracker = tr
	}

	e.clk.Store(time.Now().UnixNano())
	e.j.guard.now = func() time.Time { return time.Unix(0, e.clk.Load()) }

	return e
}

func (e *guardEnv) advance(d time.Duration) { e.clk.Add(int64(d)) }

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
	fakeWatchedTCP(t, e.root, 3000, 1234)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	e2 := newGuardEnv(t, "tcp://buildkitd.ns.svc:1234", 0)
	fakeProc(t, e2.root, 3000, 1, "buildkitd")
	fakeProc(t, e2.root, 3100, 1, "buildkitd")
	fakeWatchedTCP(t, e2.root, 3000, 1234)

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

	if !strings.Contains(e.log.String(), "no local buildkitd could be tied to the watched") {
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
	fakeWatchedTCP(t, e.root, 3000, 1234)
	fakeWatchedTCP(t, e.root, 3100, 1234)

	b, ok := e.join(e.runUnder(3000))
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)

	e2 := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e2.root, 3000, 1, "buildkitd")
	fakeProc(t, e2.root, 3100, 1, "buildkitd")
	fakeProc(t, e2.root, 3200, 1, "buildkitd")
	fakeWatchedTCP(t, e2.root, 3000, 1234)
	fakeWatchedTCP(t, e2.root, 3100, 1234)

	b, ok = e2.join(e2.runUnder(3200))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_ZeroDaemonsUnchangedWarnOnce(t *testing.T) {
	e := newGuardEnv(t, "tcp://remote:1234", 0)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(0))))
	_ = e.j.guard.snapshot(true)
	e.advance(2 * time.Second) // forced rescans are rate limited
	_ = e.j.guard.snapshot(true)

	if n := strings.Count(e.log.String(), "cannot verify which buildkitd"); n != 1 {
		t.Fatalf("warn count = %d, want 1:\n%s", n, e.log.String())
	}
}

func TestDaemonGuard_OnlyWatchedVisibleUnresolvedOwnerUnchanged(t *testing.T) {
	// containerd worker shape: only the watched daemon is visible and the
	// process tree does not lead to it. Today's behaviour is kept.
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(1))))

	if !strings.Contains(e.log.String(), "requires the OCI (runc) worker") {
		t.Fatalf("expected the worker warning:\n%s", e.log.String())
	}
}

func TestDaemonGuard_SpoofedSecondDaemonDoesNotDowngradeWatched(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)
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
	fakeWatchedTCP(t, e.root, 3000, 1234)
	fakeProc(t, e.root, 2000, 1, "sh") // CI job shell
	fakeProc(t, e.root, 3400, 2000, "buildkitd")

	b, ok := e.join(e.runUnder(3400))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_DaemonRestartReties(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	// The daemon restarts under a new pid within the cache window.
	if err := os.RemoveAll(filepath.Join(e.root, "proc", "3000")); err != nil {
		t.Fatal(err)
	}

	fakeProc(t, e.root, 3500, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3500, 1234)

	e.reg.UnlinkCgroup(guardCgID)
	e.advance(2 * time.Second) // past the rescan rate limit

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3500))))
}

func TestDaemonGuard_RetryResolvesOwnerLater(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 2*time.Second)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)

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
	fakeWatchedTCP(t, e.root, 3000, 1234)

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
	fakeWatchedTCP(t, e.root, 3000, 1234)

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

// fakeEstablished makes pid the server end of a connection from peer.
func fakeEstablished(t *testing.T, root string, pid int, peer *net.TCPAddr) {
	t.Helper()

	pdir := filepath.Join(root, "proc", strconv.Itoa(pid))
	ino := strconv.Itoa(70000 + pid)

	guardWrite(t, filepath.Join(pdir, "net", "tcp"),
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0A01010A:04D2 "+procAddr(peer.IP, peer.Port, false)+" 01 00000000:00000000 00:00000000 00000000     0        0 "+ino+" 1 0 0\n")
	guardLink(t, "socket:["+ino+"]", filepath.Join(pdir, "fd", "5"))
}

func trackedAt(e *guardEnv, ip string, port int) *net.TCPAddr {
	a := &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
	tr := NewBuildKitConnTracker()
	tr.set(a, &net.TCPAddr{IP: net.ParseIP("10.1.1.10"), Port: 1234})
	e.j.guard.tracker = tr

	return a
}

func listenAndMaybeEstablish(t *testing.T, e *guardEnv, peer *net.TCPAddr, establishedPID int) {
	t.Helper()

	for _, pid := range []int{3000, 3100} {
		fakeProc(t, e.root, pid, 1, "buildkitd")
		fakeTCPListener(t, e.root, pid, 1234)
	}

	if establishedPID != 0 {
		// Merge an ESTABLISHED row into the listener's table.
		f := filepath.Join(e.root, "proc", strconv.Itoa(establishedPID), "net", "tcp")
		b, _ := os.ReadFile(f)
		ino := strconv.Itoa(70000 + establishedPID)

		row := "   1: 0A01010A:04D2 " + procAddr(peer.IP, peer.Port, false) +
			" 01 00000000:00000000 00:00000000 00000000     0        0 " + ino + " 1 0 0\n"
		guardWrite(t, f, string(b)+row)
		guardLink(t, "socket:["+ino+"]", filepath.Join(e.root, "proc", strconv.Itoa(establishedPID), "fd", "5"))
	}
}

func TestDaemonGuard_ConnTieIgnoresSpoofListeningOnSamePort(t *testing.T) {
	// Both daemons listen on 1234 (a pod listening on the same port); only
	// the real daemon has the agent's connection.
	peer := &net.TCPAddr{IP: net.ParseIP("10.1.1.5"), Port: 40000}

	e := newGuardEnv(t, "tcp://h:1234", 0)
	trackedAt(e, "10.1.1.5", 40000)
	listenAndMaybeEstablish(t, e, peer, 3000)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000)))) // not downgraded
}

func TestDaemonGuard_ConnTieMarksOtherListenerForeign(t *testing.T) {
	peer := &net.TCPAddr{IP: net.ParseIP("10.1.1.5"), Port: 40000}

	e := newGuardEnv(t, "tcp://h:1234", 0)
	trackedAt(e, "10.1.1.5", 40000)
	listenAndMaybeEstablish(t, e, peer, 3000)

	b, ok := e.join(e.runUnder(3100))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_ConnDownKeepsLastTie(t *testing.T) {
	peer := &net.TCPAddr{IP: net.ParseIP("10.1.1.5"), Port: 40000}

	e := newGuardEnv(t, "tcp://h:1234", 0)
	trackedAt(e, "10.1.1.5", 40000)
	listenAndMaybeEstablish(t, e, peer, 3000)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	l, _ := e.j.guard.tracker.Local()
	e.j.guard.tracker.clear(l)
	e.reg.UnlinkCgroup(guardCgID)
	e.advance(20 * time.Second)

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))
}

func TestDaemonGuard_LiveConnHeldByNoLocalDaemonIsRemote(t *testing.T) {
	// The agent's connection is held by no local daemon: the watched
	// daemon is remote, so a local daemon on the same port is foreign.
	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	b, ok := e.join(e.runUnder(3000))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestDaemonGuard_PortFallbackIsNeverProof(t *testing.T) {
	// No connection information at all: a lone listener on the port is
	// only a weak tie and must not yield a link.
	e := newGuardEnv(t, "tcp://h:1234", 0)
	e.j.guard.tracker = nil
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeTCPListener(t, e.root, 3000, 1234)

	b, ok := e.join(e.runUnder(3000))
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)

	if !strings.Contains(e.log.String(), "only the listening port matches") {
		t.Fatalf("expected the weak-tie Error log:\n%s", e.log.String())
	}

	// A daemon that does not even listen on the port is provably foreign.
	e2 := newGuardEnv(t, "tcp://h:1234", 0)
	e2.j.guard.tracker = nil
	fakeProc(t, e2.root, 3000, 1, "buildkitd")
	fakeProc(t, e2.root, 3100, 1, "buildkitd")
	fakeTCPListener(t, e2.root, 3000, 1234)

	b, ok = e2.join(e2.runUnder(3100))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

// fakeUnixListenerAt is fakeUnixListener with a custom in-root socket path.
func fakeUnixListenerAt(t *testing.T, root string, pid int, procPath string) (rootfs string) {
	t.Helper()

	rootfs = filepath.Join(root, "rootfs", strconv.Itoa(pid))
	pdir := filepath.Join(root, "proc", strconv.Itoa(pid))
	ino := strconv.Itoa(90000 + pid)

	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	guardLink(t, rootfs, filepath.Join(pdir, "root"))
	guardWrite(t, filepath.Join(pdir, "net", "unix"),
		"Num RefCount Protocol Flags Type St Inode Path\n"+
			"0000: 00000002 00000000 00010000 0001 01 "+ino+" "+procPath+"\n")
	guardLink(t, "socket:["+ino+"]", filepath.Join(pdir, "fd", "3"))

	return rootfs
}

func TestDaemonGuard_UnixAbsoluteSymlinkInsideDaemonRoot(t *testing.T) {
	e := newGuardEnv(t, "tcp://x:1", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")

	// Watched daemon: /var/run -> /run (absolute) inside its root.
	rootfs := fakeUnixListenerAt(t, e.root, 3000, "/var/run/buildkit/buildkitd.sock")
	sock := filepath.Join(rootfs, "run", "buildkit", "buildkitd.sock")
	guardWrite(t, sock, "")
	guardLink(t, "/run", filepath.Join(rootfs, "var", "run"))

	// A pod-side symlink tries to point at the watched socket on the
	// agent's filesystem by absolute path.
	evil := fakeUnixListenerAt(t, e.root, 3100, "/run/buildkit/buildkitd.sock")
	guardLink(t, sock, filepath.Join(evil, "run", "buildkit", "buildkitd.sock"))

	e.j.guard.addr = "unix://" + sock

	assertLinkedB(t, guardBinding(e.join(e.runUnder(3000))))

	e.reg.UnlinkCgroup(guardCgID)
	e.advance(2 * time.Second)

	b, ok := e.join(e.runUnder(3100))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)
}

func TestStatInRootConfinesSymlinks(t *testing.T) {
	root := t.TempDir()
	guardWrite(t, filepath.Join(root, "run", "x.sock"), "")
	guardLink(t, "/run", filepath.Join(root, "var", "run"))
	guardLink(t, "../../../../etc/passwd", filepath.Join(root, "run", "escape"))

	want, ok := statID(filepath.Join(root, "run", "x.sock"))
	if !ok {
		t.Fatal("stat")
	}

	if got, ok := statInRoot(root, "/var/run/x.sock"); !ok || got != want {
		t.Errorf("in-root symlink: got %v,%v", got, ok)
	}

	if _, ok := statInRoot(root, "/run/escape"); ok {
		t.Error("escape symlink must not resolve outside root")
	}
}

func TestDaemonGuard_UnixFailsClosedWithoutOpenat2(t *testing.T) {
	old := openat2Fn
	openat2Fn = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }

	defer func() { openat2Fn = old; openat2Unavailable.Store(false) }()

	e := newGuardEnv(t, "tcp://x:1", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	sock := fakeUnixListener(t, e.root, 3000)
	e.j.guard.addr = "unix://" + sock

	b, ok := e.join(e.runUnder(3000))
	assertBlocked(t, b, ok, BuildFlagForeignDaemon)

	if !strings.Contains(e.log.String(), "openat2(RESOLVE_IN_ROOT) is unavailable") {
		t.Fatalf("expected the openat2 Error log:\n%s", e.log.String())
	}
}

// connectOnce dials via the production connect() and waits until Ready.
func connectOnce(t *testing.T, addr string, tr *BuildKitConnTracker, srvNet, srvAddr string) *grpc.ClientConn {
	t.Helper()

	ln, err := net.Listen(srvNet, srvAddr)
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer()

	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(srv.Stop)

	if addr == "" {
		addr = "tcp://" + ln.Addr().String()
	}

	w := NewAttributionWatcher(addr, NewSessionRegistry(time.Minute), nil, WithConnTracker(tr))

	conn, err := w.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn.Connect()

	for s := conn.GetState(); s != connectivity.Ready; s = conn.GetState() {
		if !conn.WaitForStateChange(ctx, s) {
			t.Fatalf("connection never became ready (state %v)", conn.GetState())
		}
	}

	return conn
}

func TestWatcherConnect_TCPTracked(t *testing.T) {
	tr := NewBuildKitConnTracker()
	conn := connectOnce(t, "", tr, "tcp", "127.0.0.1:0")

	if l, ok := tr.Local(); !ok || l == nil {
		t.Fatal("tracker did not record the tcp connection")
	}

	_ = conn.Close()

	waitFor(t, time.Second, func() bool { _, ok := tr.Local(); return !ok })
}

func TestWatcherConnect_UnixWorksWithTracker(t *testing.T) {
	tr := NewBuildKitConnTracker()
	path := filepath.Join(t.TempDir(), "bk.sock")

	connectOnce(t, "unix://"+path, tr, "unix", path)

	if _, ok := tr.Local(); ok {
		t.Fatal("unix connections are not tracked")
	}
}

func TestConnTracker_RefcountedPerLocalAddr(t *testing.T) {
	tr := NewBuildKitConnTracker()
	a := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5}

	tr.set(a, a)
	tr.set(a, a)
	tr.clear(a)

	if _, ok := tr.Local(); !ok {
		t.Fatal("one reference left: connection must stay tracked")
	}

	tr.clear(a)

	if _, ok := tr.Local(); ok {
		t.Fatal("all references released")
	}
}

func TestDaemonGuard_SuppressedRescanRetriesInsteadOfForeign(t *testing.T) {
	e := newGuardEnv(t, "tcp://h:1234", 400*time.Millisecond)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)

	// First scan (clock frozen): the owner below is a "restarted" daemon.
	_ = e.j.guard.snapshot(false)

	fakeProc(t, e.root, 3600, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3600, 1234)
	if err := os.RemoveAll(filepath.Join(e.root, "proc", "3000")); err != nil {
		t.Fatal(err)
	}

	evt := e.runUnder(3600)
	e.j.handleCreate(context.Background(), evt)

	if _, ok := e.reg.LookupByCgroupID(guardCgID); ok {
		t.Fatal("must not conclude foreign while the rescan is suppressed")
	}

	e.advance(2 * time.Second)

	waitFor(t, time.Second, func() bool {
		b, ok := e.reg.LookupByCgroupID(guardCgID)

		return ok && b.Flag == ""
	})
}

// dnsSampleEnv stages two RUN cgroups: 5000 under the watched daemon 3000
// and 5100 under daemon 3100, and returns a buildDNS sampling them.
func dnsSampleEnv(t *testing.T, guard bool) (*buildDNS, *guardEnv) {
	t.Helper()

	e := newGuardEnv(t, "tcp://h:1234", 0)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)
	fakeTCPListener(t, e.root, 3100, 1234)

	fakeProc(t, e.root, 4000, 3000, "runc")
	fakeProc(t, e.root, 4100, 3100, "runc")
	fakeProc(t, e.root, 5100, 4100, "sh")
	fakeProc(t, e.root, 5000, 4000, "sh")

	runs := filepath.Join(e.root, "runs")
	guardWrite(t, filepath.Join(runs, "a", "cgroup.procs"), "5100\n") // foreign daemon first
	guardWrite(t, filepath.Join(runs, "b", "cgroup.procs"), "5000\n")

	d := &buildDNS{
		log:        slog.New(slog.NewTextHandler(e.log, nil)),
		runPaths:   []string{runs},
		netnsInode: func(pid int) (uint64, error) { return uint64(pid), nil },
	}
	if guard {
		d.cfg.Guard = e.j.guard
	}

	return d, e
}

func TestBuildDNS_SampleOnlyWatchedDaemonSteps(t *testing.T) {
	d, _ := dnsSampleEnv(t, true)
	s := d.defaultSample()
	if len(s) != 1 || s[0].pid != 5000 {
		t.Fatalf("samples = %+v, want only the watched daemon's step 5000", s)
	}
}

func TestBuildDNS_SampleUnchangedWithoutGuard(t *testing.T) {
	d, _ := dnsSampleEnv(t, false)
	s := d.defaultSample()
	if len(s) != 2 {
		t.Fatalf("samples = %+v, want both RUN processes", s)
	}
}

func TestBuildDNS_AllStepsFilteredLogsErrorOnlyWhenUntied(t *testing.T) {
	// Tied guard, only foreign steps running: no Error.
	d, e := dnsSampleEnv(t, true)

	if err := os.RemoveAll(filepath.Join(e.root, "runs", "b")); err != nil {
		t.Fatal(err)
	}

	if s := d.defaultSample(); len(s) != 0 {
		t.Fatalf("samples = %+v, want none", s)
	}

	if strings.Contains(e.log.String(), "daemon guard could not tie") {
		t.Fatalf("tied guard must not log the Error:\n%s", e.log.String())
	}

	// Untied (port-only tie): Error, rate limited to one line.
	d, e = dnsSampleEnv(t, true)
	e.j.guard.tracker = nil

	if err := os.RemoveAll(filepath.Join(e.root, "runs", "b")); err != nil {
		t.Fatal(err)
	}

	_ = d.defaultSample()
	_ = d.defaultSample()

	if n := strings.Count(e.log.String(), "daemon guard could not tie"); n != 1 {
		t.Fatalf("error count = %d, want 1:\n%s", n, e.log.String())
	}
}

const walkWarnMsg = "has no buildkitd ancestor"

func multiDaemonEnv(t *testing.T, deferred time.Duration) *guardEnv {
	t.Helper()

	e := newGuardEnv(t, "tcp://h:1234", deferred)
	fakeProc(t, e.root, 3000, 1, "buildkitd")
	fakeProc(t, e.root, 3100, 1, "buildkitd")
	fakeWatchedTCP(t, e.root, 3000, 1234)

	return e
}

func TestDaemonGuard_EmptyProcsNoWalkWarnThenLinks(t *testing.T) {
	e := multiDaemonEnv(t, 2*time.Second)

	cg := filepath.Join(e.root, "cgroups", "ctr-guard")
	guardWrite(t, filepath.Join(cg, "cgroup.procs"), "")
	guardWrite(t, filepath.Join(cg, "cgroup.events"), "populated 0\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e.j.handleCreate(ctx, CgroupCreateEvent{ContainerID: "ctr-guard", CgroupPath: cg})

	if _, ok := e.reg.LookupByCgroupID(guardCgID); ok {
		t.Fatal("bound with empty cgroup.procs")
	}

	// The process appears a few ms later.
	fakeProc(t, e.root, 5000, 4000, "sh")
	fakeProc(t, e.root, 4000, 3000, "runc")
	stageCgroup(t, e.root, "ctr-guard", 5000, "/bin/sh\x00-c\x00npm ci\x00")

	waitFor(t, time.Second, func() bool {
		_, ok := e.reg.LookupByCgroupID(guardCgID)

		return ok
	})

	b, _ := e.reg.LookupByCgroupID(guardCgID)
	assertLinked(t, b, true)

	// Let the deferred goroutine finish before reading the log buffer.
	waitFor(t, time.Second, func() bool {
		_, busy := e.j.inflight.Load("ctr-guard")

		return !busy
	})

	if strings.Contains(e.log.String(), walkWarnMsg) {
		t.Fatalf("false walk warning:\n%s", e.log.String())
	}
}

func TestDaemonGuard_FirstPIDVanishedSecondResolves(t *testing.T) {
	e := multiDaemonEnv(t, 2*time.Second)

	fakeProc(t, e.root, 5000, 4000, "sh")
	fakeProc(t, e.root, 4000, 3000, "runc")
	cg := stageCgroup(t, e.root, "ctr-guard", 5000, "/bin/sh\x00-c\x00npm ci\x00")
	// pid 4999 already exited: listed first, absent from /proc.
	guardWrite(t, filepath.Join(cg, "cgroup.procs"), "4999\n5000\n")

	b, ok := e.join(CgroupCreateEvent{ContainerID: "ctr-guard", CgroupPath: cg})
	assertLinked(t, b, ok)

	if strings.Contains(e.log.String(), walkWarnMsg) {
		t.Fatalf("false walk warning:\n%s", e.log.String())
	}
}

func TestDaemonGuard_GenuineNoAncestorWarnsOnce(t *testing.T) {
	e := multiDaemonEnv(t, 0)

	b, ok := e.join(e.runUnder(1)) // containerd-shim style: walk ends at init
	assertBlocked(t, b, ok, BuildFlagDaemonUnverified)

	e.j.guard.noteWalkFailure()

	if n := strings.Count(e.log.String(), walkWarnMsg); n != 1 {
		t.Fatalf("walk warn count = %d, want 1:\n%s", n, e.log.String())
	}
}

func TestDaemonGuard_IsWatchedPIDVanishedNoWarn(t *testing.T) {
	e := multiDaemonEnv(t, 0)

	if e.j.guard.IsWatchedPID(7777) {
		t.Fatal("vanished pid reported watched")
	}

	if strings.Contains(e.log.String(), walkWarnMsg) {
		t.Fatalf("false walk warning:\n%s", e.log.String())
	}
}

// childArgvEnv stages a RUN shell (pid 5000) plus a live child (pid 5001)
// with the given cmdline, and a second build's pending vertex.
func childArgvEnv(t *testing.T, childCmd string) (*guardEnv, CgroupCreateEvent) {
	t.Helper()

	e := multiDaemonEnv(t, 0)
	e.reg.RegisterSession("rB", time.Unix(1000, 0), map[string]string{
		FrontendAttrKeyProjectPath: "grp/b", FrontendAttrKeyJobID: "2",
	})
	e.reg.UpsertVertex("rB", VertexState{Digest: "dB", Name: "[build 1/2] RUN make all", StartedAt: time.Unix(1010, 0)})

	fakeProc(t, e.root, 4000, 3000, "runc")
	fakeProc(t, e.root, 5001, 5000, "sh")
	guardWrite(t, filepath.Join(e.root, "proc", "5001", "cmdline"), childCmd)

	evt := e.runUnder(3000)
	guardWrite(t, filepath.Join(evt.CgroupPath, "cgroup.procs"), "5000\n5001\n")

	return e, evt
}

func TestDaemonGuard_ChildArgvOfOtherVertexDoesNotWin(t *testing.T) {
	e, evt := childArgvEnv(t, "/bin/sh\x00-c\x00make all\x00")

	b, ok := e.join(evt)
	assertLinked(t, b, ok) // the shell's vertex (dA), not rB's
}

func TestDaemonGuard_ChildMatchingNothingStillLinksShell(t *testing.T) {
	e, evt := childArgvEnv(t, "/usr/bin/node\x00setup.js\x00")

	b, ok := e.join(evt)
	assertLinked(t, b, ok)
}

func TestDaemonGuard_NoDaemonsVisibleNoWalkWarn(t *testing.T) {
	e := newGuardEnv(t, "tcp://remote:1234", 0)

	e.join(e.runUnder(1)) // definitive walk, no buildkitd anywhere

	if strings.Contains(e.log.String(), walkWarnMsg) {
		t.Fatalf("walk warning with no visible buildkitd:\n%s", e.log.String())
	}
}
