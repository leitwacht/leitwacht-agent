package enforcer

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Daemon-ancestry guard.
//
// The agent subscribes to ONE buildkitd over gRPC, but RUN cgroups are
// discovered by watching cgroup parents on the node. A second buildkitd
// that the agent does not watch can create RUN cgroups under the same
// parent (two buildkitd pods share /sys/fs/cgroup/buildkit by default).
// Joining such a cgroup to the watched daemon's sessions would be a wrong
// attribution, so the joiner resolves the buildkitd that owns each RUN
// cgroup (process ancestry) and refuses to attribute RUN steps whose
// daemon is not the watched one.
const (
	// BuildFlagForeignDaemon marks a RUN cgroup proven to belong to a
	// buildkitd other than the watched one.
	BuildFlagForeignDaemon = "foreign_daemon"
	// BuildFlagDaemonUnverified marks a RUN cgroup whose daemon could not
	// be proven to be the watched one while several buildkitd processes
	// run on the node.
	BuildFlagDaemonUnverified = "daemon_unverified"

	daemonComm         = "buildkitd"
	maxAncestryHops    = 32
	daemonDiscoveryTTL = 15 * time.Second
)

// daemonGuard decides, per RUN cgroup, whether its owning buildkitd is the
// watched daemon. The watched daemon is identified by the listening socket
// behind grpcAddr, never by process name alone. All methods are safe for
// concurrent use.
type daemonGuard struct {
	procRoot string
	addr     string
	logger   *slog.Logger
	now      func() time.Time

	tracker *BuildKitConnTracker // nil: no connection tie (port fallback only)

	mu           sync.Mutex
	scannedAt    time.Time
	scannedGen   uint64
	genAt        time.Time // when the tracked connection last changed
	daemons      []int     // every visible buildkitd process
	matching     []int     // visible daemons tied to grpcAddr
	weak         bool      // the tie is port-only (not proof)
	unsettled    bool      // live connection held by no local daemon yet
	warnedOpen   bool
	warnedNone   bool
	warnedWalk   bool
	warnedTie    bool
	warnedPort   bool
	loggedMulti  string
	loggedMultiT time.Time
}

func newDaemonGuard(grpcAddr, procRoot string, logger *slog.Logger) *daemonGuard {
	return &daemonGuard{procRoot: procRoot, addr: grpcAddr, logger: logger, now: time.Now}
}

type guardView struct {
	daemons, matching []int
	weak              bool
	// refreshed is false when a forced rescan was suppressed by the rate
	// limit.
	refreshed bool
}

// snapshot returns the cached daemon sets, rescanning when stale, when the
// tracked connection changed (always: a pre-reconnect tie is never
// authoritative), when a live connection was not yet held by any local
// daemon (re-checked after a second: accept may lag the handshake), or
// when forced. A forced rescan is never repeated within one second.
func (g *daemonGuard) snapshot(force bool) guardView {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()

	var gen uint64
	if g.tracker != nil {
		gen = g.tracker.Generation()
	}

	age := now.Sub(g.scannedAt)
	recent := !g.scannedAt.IsZero() && age < time.Second
	stale := g.scannedAt.IsZero() || age >= daemonDiscoveryTTL || gen != g.scannedGen ||
		(g.unsettled && !recent && now.Sub(g.genAt) < 5*time.Second)

	refreshed := !force

	if stale || (force && !recent) {
		if gen != g.scannedGen {
			g.genAt = now
		}

		g.refreshLocked()
		g.scannedAt, g.scannedGen = now, gen
		refreshed = true
	}

	return guardView{daemons: g.daemons, matching: g.matching, weak: g.weak, refreshed: refreshed}
}

func (g *daemonGuard) refreshLocked() {
	g.daemons = listDaemonPIDs(g.procRoot)
	g.matching, g.weak = g.tieLocked()

	if len(g.daemons) == 0 {
		if !g.warnedNone {
			g.warnedNone = true

			g.logger.Warn("buildkit daemon-ancestry guard cannot verify which buildkitd owns RUN cgroups: "+
				"no buildkitd process visible (agent without hostPID, or a remote buildkitd); "+
				"attribution proceeds unverified",
				"proc_root", g.procRoot)
		}

		return
	}

	if len(g.matching) == 0 && !g.warnedTie {
		g.warnedTie = true

		g.logger.Error("buildkit daemon-ancestry guard: no local buildkitd could be tied to the watched "+
			"address; RUN steps of local buildkitd processes will be left unattributed. Either the watched "+
			"daemon is not on this node, or the agent lacks permission to read other processes' fd tables "+
			"and root (needs CAP_SYS_PTRACE-level access; the shipped charts run privileged), or the "+
			"connection could not be matched (try the unix socket form)",
			"grpc_addr", g.addr, "local_daemons", len(g.daemons))
	}

	if len(g.daemons) >= 2 {
		g.logMultiLocked()
	}
}

// logMultiLocked reports several buildkitd processes at Error, with the pid
// and cgroup of each, when the set changes or once a minute.
func (g *daemonGuard) logMultiLocked() {
	key := fmt.Sprint(g.daemons)
	now := g.now()

	if key == g.loggedMulti && now.Sub(g.loggedMultiT) < time.Minute {
		return
	}

	g.loggedMulti, g.loggedMultiT = key, now

	attrs := []any{"count", len(g.daemons), "watched_pids", fmt.Sprint(g.matching)}

	for _, d := range g.daemons {
		attrs = append(attrs, "pid_"+strconv.Itoa(d)+"_cgroup", readCgroupLine(g.procRoot, d))
	}

	g.logger.Error("several buildkitd processes visible on this node; only RUN steps whose "+
		"buildkitd owns the watched address are attributed", attrs...)
}

// tieLocked finds the local daemons on the other end of grpcAddr; weak is
// true when the tie is only a port match (never proof).
//   - unix:// address: the daemon holding a listener on that socket file,
//     resolved inside its root. Without openat2 nothing matches.
//   - tcp, live agent connection: the daemon holding the server end of it.
//     If no local daemon does, the watched daemon is remote and nothing
//     matches (every local daemon is foreign).
//   - tcp, connection down: the previous tie is kept for daemons still
//     alive.
//   - tcp, no connection information at all: the daemons listening on the
//     port, as a weak tie.
func (g *daemonGuard) tieLocked() (pids []int, weak bool) {
	g.unsettled = false

	if strings.HasPrefix(g.addr, "unix:") {
		for _, d := range g.daemons {
			if unixListens(g.procRoot, d, g.addr) {
				pids = append(pids, d)
			}
		}

		if openat2Unavailable.Load() && !g.warnedOpen {
			g.warnedOpen = true

			g.logger.Error("buildkit daemon-ancestry guard: openat2(RESOLVE_IN_ROOT) is unavailable " +
				"(old kernel or seccomp); the unix socket tie fails closed and local buildkitd steps " +
				"are left unattributed")
		}

		return pids, false
	}

	if g.tracker != nil {
		if local, ok := g.tracker.Local(); ok {
			for _, d := range g.daemons {
				if tcpEstablishedFrom(g.procRoot, d, local) {
					pids = append(pids, d)
				}
			}

			g.unsettled = len(pids) == 0

			return pids, false
		}

		// Connection down: keep the last tie for daemons still alive.
		for _, d := range g.matching {
			if pidIn(g.daemons, d) {
				pids = append(pids, d)
			}
		}

		if len(pids) > 0 {
			return pids, g.weak
		}
	}

	for _, d := range g.daemons {
		if tcpListensOn(g.procRoot, d, g.addr) {
			pids = append(pids, d)
		}
	}

	if len(pids) > 0 && !g.warnedPort {
		g.warnedPort = true

		g.logger.Error("buildkit daemon-ancestry guard: no connection information to tie the watched "+
			"daemon; only the listening port matches, which is not proof. Steps of those daemons are "+
			"left unverified",
			"grpc_addr", g.addr, "candidates", len(pids))
	}

	return pids, true
}

func readCgroupLine(procRoot string, pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "unknown"
	}

	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")

	return line
}

func pidIn(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}

	return false
}

// verdict returns "" when the RUN cgroup may be attributed to the watched
// daemon, or the BuildFlag to stamp on it. owner is the outermost buildkitd
// found by ancestry when ownerKnown. retry is true (non-final attempts only)
// when the owner does not match but a forced rescan was suppressed by the
// rate limit, so a later attempt may see a restarted daemon.
func (g *daemonGuard) verdict(owner int, ownerKnown, final bool) (flag string, retry bool) {
	v := g.snapshot(false)

	if ownerKnown && !pidIn(v.matching, owner) {
		// The watched daemon may have restarted (new pid): re-tie.
		v = g.snapshot(true)
		if !v.refreshed && !final && !pidIn(v.matching, owner) {
			return "", true
		}
	}

	if len(v.daemons) == 0 {
		return "", false
	}

	if !ownerKnown {
		g.noteWalkFailure()

		// Only the watched daemon is visible: nothing else could own the
		// step (also covers workers whose process tree hides buildkitd).
		if !v.weak && len(v.daemons) == 1 && len(v.matching) == 1 {
			return "", false
		}

		return BuildFlagDaemonUnverified, false
	}

	switch {
	case !pidIn(v.matching, owner):
		return BuildFlagForeignDaemon, false
	case v.weak || len(v.matching) != 1:
		return BuildFlagDaemonUnverified, false
	default:
		return "", false
	}
}

func (g *daemonGuard) noteWalkFailure() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.warnedWalk {
		return
	}

	g.warnedWalk = true

	g.logger.Warn("buildkit daemon-ancestry guard: a RUN process has no buildkitd ancestor. "+
		"The guard requires the OCI (runc) worker; with the containerd worker the process tree "+
		"does not lead to buildkitd and steps are left unverified when other buildkitd processes exist",
		"proc_root", g.procRoot)
}

// listDaemonPIDs scans procRoot for processes named buildkitd.
func listDaemonPIDs(procRoot string) []int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}

	var out []int

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}

		if isDaemonProc(procRoot, pid) {
			out = append(out, pid)
		}
	}

	return out
}

func isDaemonProc(procRoot string, pid int) bool {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))

	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		if strings.TrimSpace(string(b)) == daemonComm {
			return true
		}
	}

	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		return filepath.Base(exe) == daemonComm
	}

	return false
}

// unixListens reports whether process pid owns a listening unix socket
// for addr (unix://path). The path is resolved inside the daemon's own root
// (never following links out of it) and compared by device+inode with the
// agent's view of addr; the daemon must hold the socket in its fd table.
func unixListens(procRoot string, pid int, addr string) bool {
	path := strings.TrimPrefix(strings.TrimPrefix(addr, "unix:"), "//")

	want, ok := statID(path)
	if !ok {
		return false
	}

	p := strconv.Itoa(pid)
	root := filepath.Join(procRoot, p, "root")

	for _, e := range listeningSockets(filepath.Join(procRoot, p, "net", "unix"), 6, 7, 3, "00010000") {
		if e.path == "" || strings.HasPrefix(e.path, "@") {
			continue
		}

		if got, ok := statInRoot(root, e.path); ok && got == want && holdsSocket(procRoot, pid, e.inode) {
			return true
		}
	}

	return false
}

// tcpListensOn is the port fallback: pid holds a LISTEN socket on addr's port.
func tcpListensOn(procRoot string, pid int, addr string) bool {
	_, port, err := net.SplitHostPort(strings.TrimPrefix(addr, "tcp://"))
	if err != nil {
		return false
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}

	for _, f := range []string{"tcp", "tcp6"} {
		for _, e := range listeningSockets(filepath.Join(procRoot, strconv.Itoa(pid), "net", f), 9, 1, 3, "0A") {
			if strings.HasSuffix(e.path, ":"+fmt.Sprintf("%04X", n)) && holdsSocket(procRoot, pid, e.inode) {
				return true
			}
		}
	}

	return false
}

// procAddr renders ip:port the way /proc/net/tcp{,6} does (each 32-bit
// word byte-reversed, upper-case hex).
func procAddr(ip net.IP, port int, v6 bool) string {
	b := ip.To4()
	if v6 || b == nil {
		b = ip.To16()
	}

	var sb strings.Builder

	for i := 0; i+3 < len(b); i += 4 {
		fmt.Fprintf(&sb, "%02X%02X%02X%02X", b[i+3], b[i+2], b[i+1], b[i])
	}

	fmt.Fprintf(&sb, ":%04X", port)

	return sb.String()
}

// tcpEstablishedFrom reports whether pid holds an ESTABLISHED socket whose
// peer is the agent's connection (agent local address), i.e. pid is the
// server end of the agent's own gRPC connection.
func tcpEstablishedFrom(procRoot string, pid int, local net.Addr) bool {
	ta, ok := local.(*net.TCPAddr)
	if !ok {
		return false
	}

	for _, f := range []struct {
		name string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}} {
		if !f.v6 && ta.IP.To4() == nil {
			continue
		}

		want := procAddr(ta.IP, ta.Port, f.v6)

		for _, e := range establishedSockets(filepath.Join(procRoot, strconv.Itoa(pid), "net", f.name)) {
			if e.path == want && holdsSocket(procRoot, pid, e.inode) {
				return true
			}
		}
	}

	return false
}

// establishedSockets returns ESTABLISHED rows of a /proc/net/tcp table with
// path set to the REMOTE address.
func establishedSockets(file string) []sockEntry {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	var out []sockEntry

	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 || f[3] != "01" {
			continue
		}

		out = append(out, sockEntry{inode: f[9], path: f[2]})
	}

	return out
}

type sockEntry struct {
	inode string
	path  string // unix: socket path; tcp: local "ADDR:PORT"
}

// listeningSockets parses a /proc/net table. inodeCol and pathCol are field
// indexes; stCol/stWant select listening rows (unix: Flags 00010000,
// tcp: st 0A).
func listeningSockets(file string, inodeCol, pathCol, stCol int, stWant string) []sockEntry {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	var out []sockEntry

	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue
		}

		f := strings.Fields(line)
		if len(f) <= stCol || f[stCol] != stWant {
			continue
		}

		e := sockEntry{}
		if len(f) > inodeCol {
			e.inode = f[inodeCol]
		}

		if len(f) > pathCol {
			e.path = f[pathCol]
		}

		out = append(out, e)
	}

	return out
}

// holdsSocket reports whether pid has an fd for the socket inode.
func holdsSocket(procRoot string, pid int, inode string) bool {
	if inode == "" {
		return false
	}

	dir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")

	fds, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	want := "socket:[" + inode + "]"

	for _, fd := range fds {
		if l, err := os.Readlink(filepath.Join(dir, fd.Name())); err == nil && l == want {
			return true
		}
	}

	return false
}

// ancestorDaemon walks PPid upward from pid (inclusive) and returns the
// OUTERMOST buildkitd process on the chain: the real daemon, even when a
// RUN process renamed itself buildkitd (it sits deeper in the chain).
// Expected tree for a rootful runc worker: buildkitd -> runc -> RUN
// process. definitive is true when the walk reached the top of the tree
// cleanly, so retrying cannot change a not-found result; it is false after
// a read error or the hop limit (process gone mid-walk).
func ancestorDaemon(procRoot string, pid int) (owner int, found, definitive bool) {
	for hops := 0; hops < maxAncestryHops; hops++ {
		if pid <= 1 {
			return owner, found, true
		}

		if isDaemonProc(procRoot, pid) {
			owner, found = pid, true
		}

		ppid, err := readPPid(procRoot, pid)
		if err != nil || ppid == pid {
			return owner, found, false
		}

		pid = ppid
	}

	return owner, found, false
}

func readPPid(procRoot string, pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, fmt.Errorf("read status: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return 0, fmt.Errorf("parse PPid: %w", err)
			}

			return n, nil
		}
	}

	return 0, fmt.Errorf("no PPid in status of pid %d", pid)
}

// isDaemonBlockFlag reports whether f is a daemon-guard flag. Such rows
// are never attributed at any level (vertex, session or project).
func isDaemonBlockFlag(f string) bool {
	return f == BuildFlagForeignDaemon || f == BuildFlagDaemonUnverified
}

// WithDaemonGuard enables the daemon-ancestry guard for the watched
// buildkitd reached at grpcAddr (see the package comment above).
func WithDaemonGuard(grpcAddr string) JoinerOption {
	return func(j *CgroupJoiner) { j.guardAddr, j.guardOn = grpcAddr, true }
}

// WithDaemonConnTracker ties the watched daemon to the agent's own gRPC
// connection (the watcher must be built with WithConnTracker on the same
// tracker). Without it, tcp addresses fall back to port matching.
func WithDaemonConnTracker(t *BuildKitConnTracker) JoinerOption {
	return func(j *CgroupJoiner) { j.guardTracker = t }
}

// linkDaemonBlocked records an unattributable binding for a RUN cgroup
// whose daemon is not (provably) the watched one: no vertex, no
// candidates, not ambiguous, so the policy binder classifies it unattributed and the row is filed build_unattributed and the
// session-level fallback skips it.
func (j *CgroupJoiner) linkDaemonBlocked(cgroupID uint64, evt CgroupCreateEvent, flag string) {
	j.linkCgroup(cgroupID, CgroupBinding{
		ContainerID: evt.ContainerID,
		CgroupPath:  evt.CgroupPath,
		Strength:    StrengthAmbiguous,
		Flag:        flag,
	})

	j.logger.Warn("buildkit RUN cgroup not attributed: its buildkitd is not the watched daemon",
		"flag", flag,
		"cgroup_id", cgroupID,
		"container_id", evt.ContainerID,
	)
}
