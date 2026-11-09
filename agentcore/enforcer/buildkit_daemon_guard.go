package enforcer

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
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

// pinnedDaemonRe extracts the daemon PID from a gRPC address that points
// through a host process root (unix:///proc/<pid>/root/...).
var pinnedDaemonRe = regexp.MustCompile(`^unix:(?://)?/proc/(\d+)/root/`)

// daemonGuard decides, per RUN cgroup, whether its owning buildkitd is the
// watched daemon. All methods are safe for concurrent use.
type daemonGuard struct {
	procRoot string
	logger   *slog.Logger
	now      func() time.Time
	pinned   int // watched daemon PID from the gRPC address, 0 if none

	mu         sync.Mutex
	scannedAt  time.Time
	daemons    []int
	warnedNone bool
}

func newDaemonGuard(grpcAddr, procRoot string, logger *slog.Logger) *daemonGuard {
	g := &daemonGuard{procRoot: procRoot, logger: logger, now: time.Now}

	if m := pinnedDaemonRe.FindStringSubmatch(grpcAddr); m != nil {
		g.pinned, _ = strconv.Atoi(m[1])
	}

	return g
}

// discover returns the host PIDs whose comm is buildkitd, cached for
// daemonDiscoveryTTL unless force is set.
func (g *daemonGuard) discover(force bool) []int {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !force && !g.scannedAt.IsZero() && g.now().Sub(g.scannedAt) < daemonDiscoveryTTL {
		return g.daemons
	}

	g.daemons = listDaemonPIDs(g.procRoot)
	g.scannedAt = g.now()

	if len(g.daemons) == 0 && !g.warnedNone {
		g.warnedNone = true

		g.logger.Warn("buildkit daemon-ancestry guard cannot verify which buildkitd owns RUN cgroups: "+
			"no buildkitd process visible (agent without hostPID, or a remote buildkitd); "+
			"attribution proceeds unverified",
			"proc_root", g.procRoot)
	}

	return g.daemons
}

// verdict returns "" when the RUN cgroup may be attributed to the watched
// daemon, or the BuildFlag to stamp on it. owner is the buildkitd PID found
// by ancestry when ownerKnown.
func (g *daemonGuard) verdict(owner int, ownerKnown bool) string {
	if g.pinned > 0 {
		switch {
		case !ownerKnown:
			return BuildFlagDaemonUnverified
		case owner == g.pinned:
			return ""
		default:
			return BuildFlagForeignDaemon
		}
	}

	ds := g.discover(false)

	switch len(ds) {
	case 0:
		return ""
	case 1:
		if !ownerKnown || owner == ds[0] {
			return ""
		}

		// The sole daemon may have restarted since the last scan.
		ds = g.discover(true)
		if len(ds) == 1 && owner == ds[0] {
			return ""
		}

		if len(ds) <= 1 {
			return BuildFlagForeignDaemon
		}

		return BuildFlagDaemonUnverified
	default:
		// Several daemons and no way to tell which one the gRPC address
		// reaches: nothing can be proven.
		return BuildFlagDaemonUnverified
	}
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

// ancestorDaemon walks PPid upward from pid (inclusive) and returns the
// first buildkitd process. Expected tree for a rootful runc worker:
// buildkitd -> runc -> RUN process. ok is false when none is found within
// maxAncestryHops (process gone, no hostPID, foreign pid namespace).
func ancestorDaemon(procRoot string, pid int) (int, bool) {
	for hops := 0; hops < maxAncestryHops && pid > 1; hops++ {
		if isDaemonProc(procRoot, pid) {
			return pid, true
		}

		ppid, err := readPPid(procRoot, pid)
		if err != nil || ppid == pid {
			return 0, false
		}

		pid = ppid
	}

	return 0, false
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
// candidates, so the policy binder classifies it unattributed and the
// session-level fallback skips it.
func (j *CgroupJoiner) linkDaemonBlocked(cgroupID uint64, evt CgroupCreateEvent, flag string) {
	j.linkCgroup(cgroupID, CgroupBinding{
		ContainerID: evt.ContainerID,
		CgroupPath:  evt.CgroupPath,
		Ambiguous:   true,
		Strength:    StrengthAmbiguous,
		Flag:        flag,
	})

	j.logger.Warn("buildkit RUN cgroup not attributed: its buildkitd is not the watched daemon",
		"flag", flag,
		"cgroup_id", cgroupID,
		"container_id", evt.ContainerID,
	)
}
