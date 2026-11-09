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

	mu           sync.Mutex
	scannedAt    time.Time
	forcedAt     time.Time
	daemons      []int // every visible buildkitd process
	matching     []int // visible daemons that listen on grpcAddr
	warnedNone   bool
	warnedWalk   bool
	warnedTie    bool
	loggedMulti  string
	loggedMultiT time.Time
}

func newDaemonGuard(grpcAddr, procRoot string, logger *slog.Logger) *daemonGuard {
	return &daemonGuard{procRoot: procRoot, addr: grpcAddr, logger: logger, now: time.Now}
}

// snapshot returns the cached daemon sets, rescanning when stale or forced.
// A forced rescan is rate-limited to once per second.
func (g *daemonGuard) snapshot(force bool) (daemons, matching []int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	stale := g.scannedAt.IsZero() || now.Sub(g.scannedAt) >= daemonDiscoveryTTL
	canForce := force && (g.forcedAt.IsZero() || now.Sub(g.forcedAt) >= time.Second)

	if stale || canForce {
		if canForce {
			g.forcedAt = now
		}

		g.refreshLocked()
		g.scannedAt = now
	}

	return g.daemons, g.matching
}

func (g *daemonGuard) refreshLocked() {
	g.daemons = listDaemonPIDs(g.procRoot)
	g.matching = nil

	for _, d := range g.daemons {
		if daemonListensOn(g.procRoot, d, g.addr) {
			g.matching = append(g.matching, d)
		}
	}

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

		g.logger.Error("buildkit daemon-ancestry guard: no local buildkitd listens on the watched address; "+
			"RUN steps of local buildkitd processes will be left unattributed. If the watched daemon is "+
			"local, the address does not match its listener (a Service port that differs from targetPort "+
			"never matches): use the unix socket form or the same port",
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
// found by ancestry when ownerKnown.
func (g *daemonGuard) verdict(owner int, ownerKnown bool) string {
	daemons, matching := g.snapshot(false)

	if ownerKnown && !pidIn(matching, owner) {
		// The watched daemon may have restarted (new pid): re-tie once.
		daemons, matching = g.snapshot(true)
	}

	if len(daemons) == 0 {
		return ""
	}

	if !ownerKnown {
		g.noteWalkFailure()

		// Only the watched daemon is visible: nothing else could own the
		// step (also covers workers whose process tree hides buildkitd).
		if len(daemons) == 1 && len(matching) == 1 {
			return ""
		}

		return BuildFlagDaemonUnverified
	}

	switch {
	case !pidIn(matching, owner):
		return BuildFlagForeignDaemon
	case len(matching) == 1:
		return ""
	default:
		return BuildFlagDaemonUnverified
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

// daemonListensOn reports whether process pid owns a listening socket for
// addr (unix:// path or tcp:// port). The socket must be held in pid's fd
// table, so a process that merely shares the network namespace never matches.
func daemonListensOn(procRoot string, pid int, addr string) bool {
	p := strconv.Itoa(pid)

	switch {
	case strings.HasPrefix(addr, "unix:"):
		path := strings.TrimPrefix(strings.TrimPrefix(addr, "unix:"), "//")

		want, err := os.Stat(path)
		if err != nil {
			return false
		}

		for _, e := range listeningSockets(filepath.Join(procRoot, p, "net", "unix"), 6, 7, 3, "00010000") {
			if e.path == "" || strings.HasPrefix(e.path, "@") {
				continue
			}

			got, err := os.Stat(filepath.Join(procRoot, p, "root", e.path))
			if err == nil && os.SameFile(want, got) && holdsSocket(procRoot, pid, e.inode) {
				return true
			}
		}

		return false
	case strings.HasPrefix(addr, "tcp:"):
		_, port, err := net.SplitHostPort(strings.TrimPrefix(addr, "tcp://"))
		if err != nil {
			return false
		}

		n, err := strconv.Atoi(port)
		if err != nil {
			return false
		}

		for _, f := range []string{"tcp", "tcp6"} {
			for _, e := range listeningSockets(filepath.Join(procRoot, p, "net", f), 9, 1, 3, "0A") {
				if strings.HasSuffix(e.path, ":"+fmt.Sprintf("%04X", n)) && holdsSocket(procRoot, pid, e.inode) {
					return true
				}
			}
		}
	}

	return false
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
