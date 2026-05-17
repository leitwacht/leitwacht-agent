package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupCreateEvent is the signal emitted by the platform-specific
// event source when a new cgroup directory appears under a watched
// buildkit-cgroup-parent path. The cgroup name (== runc container
// ID) is in ContainerID; CgroupPath is the absolute path of the
// newly-created directory.
type CgroupCreateEvent struct {
	ContainerID string
	CgroupPath  string
}

// CgroupRemoveEvent fires when a watched cgroup directory disappears
// (runc tearing down a finished RUN container). The join layer
// uses this to unlink the cgroup_id binding so the index doesn't
// grow unbounded.
type CgroupRemoveEvent struct {
	ContainerID string
	CgroupPath  string
}

// CgroupEventSource is the platform abstraction. Linux provides an
// inotify-backed implementation in buildkit_cgroup_join_linux.go;
// non-Linux platforms get a stub that returns ErrCgroupJoinUnsupported.
type CgroupEventSource interface {
	// Run consumes the source's lifetime: it blocks until ctx is
	// cancelled or a fatal error surfaces. Implementations send on
	// creates/removes as events arrive. Channels are closed on
	// Run exit.
	Run(ctx context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) error
}

// ErrCgroupJoinUnsupported is returned by the stub event source on
// non-Linux builds, and by the Linux event source when no watch
// paths are configured.
var ErrCgroupJoinUnsupported = errors.New("buildkit cgroup join is not supported on this platform or no watch paths configured")

// defaultStatFn is the platform-resolved cgroup-id stat function.
// On Linux it returns the inode of the cgroup directory (cgroup v2
// uses the inode as the cgroup_id); on non-Linux it returns
// ErrCgroupJoinUnsupported. Build-tagged init() in
// buildkit_cgroup_join_{linux,stub}.go sets it.
var defaultStatFn func(path string) (uint64, error)

// CgroupJoiner is the orchestrator: it owns the event source, reads
// each new cgroup's first PID's cmdline, matches against pending
// vertices in the SessionRegistry, and links the resulting binding.
//
// Concurrency: a single goroutine consumes events serially. Matching
// against the registry is read-only on the registry's mutex; linking
// is a single write. The event source produces creates/removes on
// buffered channels so a slow match path can't drop kernel events
// (the buffer is sized to the configured channel capacity).
type CgroupJoiner struct {
	registry *SessionRegistry
	logger   *slog.Logger
	source   CgroupEventSource

	// channelBuffer controls the create/remove channel capacity.
	// Default 256 — generous given typical max-parallelism per
	// buildkitd is in the low tens.
	channelBuffer int

	// procRoot is "/proc" in production; tests override.
	procRoot string

	// statFn returns (inode, err) for a cgroup path. Defaults to
	// os.Stat + Sys().Ino via the platform helper; tests override
	// to inject deterministic ids.
	statFn func(path string) (uint64, error)
}

// JoinerOption tunes a CgroupJoiner at construction.
type JoinerOption func(*CgroupJoiner)

// WithProcRoot overrides the /proc mount path. Test-only.
func WithProcRoot(root string) JoinerOption {
	return func(j *CgroupJoiner) { j.procRoot = root }
}

// WithStatFn overrides the cgroup-id resolver. Test-only.
func WithStatFn(fn func(path string) (uint64, error)) JoinerOption {
	return func(j *CgroupJoiner) { j.statFn = fn }
}

// WithChannelBuffer overrides the create/remove channel capacity.
func WithChannelBuffer(n int) JoinerOption {
	return func(j *CgroupJoiner) { j.channelBuffer = n }
}

// NewCgroupJoiner returns a joiner wired to the supplied registry
// and platform event source.
func NewCgroupJoiner(registry *SessionRegistry, source CgroupEventSource, logger *slog.Logger, opts ...JoinerOption) *CgroupJoiner {
	if logger == nil {
		logger = slog.Default()
	}

	j := &CgroupJoiner{
		registry:      registry,
		logger:        logger,
		source:        source,
		channelBuffer: 256,
		procRoot:      "/proc",
		statFn:        defaultStatFn,
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

// Run blocks until ctx is cancelled or the event source returns a
// fatal error. Per-event errors (cgroup gone, PID exited, cmdline
// unreadable) are logged at debug level and skipped — the create
// event likely fired for something that wasn't a runc RUN container,
// which is normal and harmless.
func (j *CgroupJoiner) Run(ctx context.Context) error {
	creates := make(chan CgroupCreateEvent, j.channelBuffer)
	removes := make(chan CgroupRemoveEvent, j.channelBuffer)

	sourceErr := make(chan error, 1)
	go func() {
		sourceErr <- j.source.Run(ctx, creates, removes)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sourceErr:
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("cgroup event source: %w", err)
			}

			return nil
		case evt, ok := <-creates:
			if !ok {
				return nil
			}

			j.handleCreate(evt)
		case evt, ok := <-removes:
			if !ok {
				return nil
			}

			j.handleRemove(evt)
		}
	}
}

func (j *CgroupJoiner) handleCreate(evt CgroupCreateEvent) {
	cgroupID, err := j.statFn(evt.CgroupPath)
	if err != nil {
		// Cgroup may have been removed already (very short-lived
		// containers). Not interesting at info level.
		j.logger.Debug("cgroup stat failed", "path", evt.CgroupPath, "err", err)

		return
	}

	pid, err := readFirstPID(evt.CgroupPath)
	if err != nil {
		j.logger.Debug("cgroup procs unreadable", "path", evt.CgroupPath, "err", err)

		return
	}

	cmdline, err := readCmdline(j.procRoot, pid)
	if err != nil {
		j.logger.Debug("pid cmdline unreadable", "pid", pid, "err", err)

		return
	}

	pending := j.registry.PendingVertices()
	matches := matchPendingByCmdline(pending, cmdline)

	switch len(matches) {
	case 0:
		// Not a buildkit RUN, or vertex hasn't streamed yet
		// (race; status events arrive slightly after the runc
		// fork). Drop silently — the cgroup index just doesn't
		// gain an entry, and egress events for this cgroup are
		// emitted unattributed.
		return
	case 1:
		m := matches[0]
		j.registry.LinkCgroup(cgroupID, CgroupBinding{
			SessionRef:    m.SessionRef,
			VertexDigest:  m.VertexDigest,
			VertexName:    m.VertexName,
			ContainerID:   evt.ContainerID,
			FrontendAttrs: m.FrontendAttrs,
		})
	default:
		// Tiebreaker: environ. Read /proc/<pid>/environ and pick
		// the candidate whose FrontendAttrs values appear in the
		// process environment. Falls through to ambiguous if the
		// tiebreaker also yields >1 (or 0 — the more likely case
		// when neither side's attrs surface in env).
		environ, _ := readEnviron(j.procRoot, pid)
		refined := tiebreakByEnviron(matches, environ)
		if len(refined) == 1 {
			m := refined[0]
			j.registry.LinkCgroup(cgroupID, CgroupBinding{
				SessionRef:    m.SessionRef,
				VertexDigest:  m.VertexDigest,
				VertexName:    m.VertexName,
				ContainerID:   evt.ContainerID,
				FrontendAttrs: m.FrontendAttrs,
			})

			return
		}

		j.registry.LinkCgroup(cgroupID, CgroupBinding{
			ContainerID:         evt.ContainerID,
			Ambiguous:           true,
			AmbiguousCandidates: candidatesFromMatches(matches),
		})

		j.logger.Info("cgroup-to-vertex join is ambiguous",
			"container_id", evt.ContainerID,
			"candidates", len(matches),
		)
	}
}

func (j *CgroupJoiner) handleRemove(evt CgroupRemoveEvent) {
	// Resolve the cgroup id by walking the index — the path's
	// inode is already gone by the time the remove event fires,
	// so a fresh stat would either fail or return a recycled
	// inode (rare but possible). Scanning by ContainerID is O(n)
	// over the index, which is bounded by max-parallelism.
	j.registry.mu.Lock()
	defer j.registry.mu.Unlock()

	for id, binding := range j.registry.cgroupIndex {
		if binding.ContainerID == evt.ContainerID {
			delete(j.registry.cgroupIndex, id)

			return
		}
	}
}

// readFirstPID reads cgroupPath/cgroup.procs and returns the first
// PID. Empty cgroups (no processes yet) return os.ErrProcessDone-
// style errors via the underlying read.
func readFirstPID(cgroupPath string) (int, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		return 0, fmt.Errorf("read cgroup.procs: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		pid, err := strconv.Atoi(line)
		if err != nil {
			return 0, fmt.Errorf("parse pid %q: %w", line, err)
		}

		return pid, nil
	}

	return 0, errors.New("cgroup.procs is empty")
}

// readCmdline returns the contents of /proc/<pid>/cmdline with the
// usual NUL byte separators replaced by spaces. Returned string is
// trimmed of any trailing NUL.
func readCmdline(procRoot string, pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return "", fmt.Errorf("read cmdline: %w", err)
	}

	// cmdline is NUL-separated; collapse to spaces and trim.
	s := strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")

	return s, nil
}

// readEnviron returns /proc/<pid>/environ as a map[KEY]VALUE.
// Unreadable environ (perm denied on systemd-like setups, or pid
// exited) returns an empty map without an error — callers treat it
// as "no tiebreaker available".
func readEnviron(procRoot string, pid int) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil, fmt.Errorf("read environ: %w", err)
	}

	out := make(map[string]string)

	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}

		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}

		out[kv[:eq]] = kv[eq+1:]
	}

	return out, nil
}

// matchPendingByCmdline returns the pending vertices whose Name
// contains a RUN command matching cmdline. BuildKit names look like:
//
//	"[build 5/12] RUN npm ci"
//	"[stage-final 2/4] COPY --from=build /out /"
//
// Only "RUN" vertices match — COPY/FROM/ARG don't spawn runc
// containers and therefore don't surface as cgroup creates. The
// match strips the bracket prefix and the leading "RUN " and then
// checks whether cmdline contains the remainder.
//
// BuildKit invokes RUN via `/bin/sh -c "<cmd>"`, so cmdline is
// typically "sh -c <cmd>" or "/bin/sh -c <cmd>". The substring check
// against the RUN command tolerates either shape.
func matchPendingByCmdline(pending []PendingVertex, cmdline string) []PendingVertex {
	var out []PendingVertex

	for _, v := range pending {
		cmd := extractRunCommand(v.VertexName)
		if cmd == "" {
			continue
		}

		if cmdlineContains(cmdline, cmd) {
			out = append(out, v)
		}
	}

	return out
}

// extractRunCommand returns the command portion of a BuildKit RUN
// vertex name. Returns "" for non-RUN vertices.
func extractRunCommand(vertexName string) string {
	// Drop the bracketed prefix if present: "[stage 1/2] RUN ..."
	rest := vertexName
	if i := strings.IndexByte(rest, ']'); i > 0 && strings.HasPrefix(rest, "[") {
		rest = strings.TrimLeft(rest[i+1:], " ")
	}

	const runPrefix = "RUN "
	if !strings.HasPrefix(rest, runPrefix) {
		return ""
	}

	return strings.TrimSpace(rest[len(runPrefix):])
}

func cmdlineContains(cmdline, runCmd string) bool {
	if runCmd == "" {
		return false
	}

	return strings.Contains(cmdline, runCmd)
}

// tiebreakByEnviron narrows a multi-match set to candidates whose
// FrontendAttrs values appear in the process environment. Each
// FrontendAttrs entry (e.g. build-arg: KEY=VALUE) is checked against
// /proc/<pid>/environ; a candidate survives if all its attrs match.
// When no candidate has FrontendAttrs, all candidates survive
// (degraded — caller treats the result as still-ambiguous).
func tiebreakByEnviron(matches []PendingVertex, environ map[string]string) []PendingVertex {
	if len(environ) == 0 {
		return matches
	}

	var refined []PendingVertex

	for _, m := range matches {
		if len(m.FrontendAttrs) == 0 {
			refined = append(refined, m)

			continue
		}

		allMatch := true

		for k, want := range m.FrontendAttrs {
			// FrontendAttrs keys include things like
			// "build-arg:FOO" — strip the "build-arg:" prefix to
			// get the env-var name BuildKit injected.
			envKey := strings.TrimPrefix(k, "build-arg:")

			got, ok := environ[envKey]
			if !ok || got != want {
				allMatch = false

				break
			}
		}

		if allMatch {
			refined = append(refined, m)
		}
	}

	if len(refined) == 0 {
		// All candidates had FrontendAttrs and none matched —
		// treat as if no tiebreaker was available.
		return matches
	}

	return refined
}

func candidatesFromMatches(matches []PendingVertex) []AmbiguousCandidate {
	out := make([]AmbiguousCandidate, 0, len(matches))
	for _, m := range matches {
		out = append(out, AmbiguousCandidate{
			SessionRef:   m.SessionRef,
			VertexDigest: m.VertexDigest,
			VertexName:   m.VertexName,
		})
	}

	return out
}
