package handler

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultFreezeTimeout bounds how long the handler waits for a
	// container's cgroup to report frozen, and is the budget it grants
	// policy lookup plus attach before the container is killed (block
	// mode) or released (audit mode).
	DefaultFreezeTimeout = 5 * time.Second

	// freezeHoldSlack is added to the larger of the freeze timeout and
	// handleStartTimeout to form the hard upper bound on how long any
	// container stays frozen. When it expires the container is thawed no
	// matter what state the handler is in: a frozen job is an outage, an
	// unenforced job is the pre-freeze status quo.
	freezeHoldSlack = 5 * time.Second

	freezePollMin = time.Millisecond
	freezePollMax = 16 * time.Millisecond

	// DefaultFreezeStateDir holds one marker per held container so a
	// restarted agent can release what a crashed one left frozen. It must
	// survive an agent process restart (tmpfs under /run does; on K8s mount
	// it from the host).
	DefaultFreezeStateDir = "/run/leitwacht/frozen"

	// thawTimeout bounds the runtime-API unpause fallback, which runs on a
	// fresh context because the handler's own may already be cancelled.
	thawTimeout = 5 * time.Second
)

var (
	// ErrFreezeUnavailable means neither the cgroup v2 freezer nor the
	// runtime pause API can be used for this container (cgroup v1,
	// kernel without cgroup.freeze, no pauser wired). The caller proceeds
	// unfrozen: refusing to run every container on such a host would turn
	// a hardening gap into an outage.
	ErrFreezeUnavailable = errors.New("container freeze unavailable")

	// ErrFreezeTimeout means the cgroup did not report frozen in time.
	ErrFreezeTimeout = errors.New("timed out waiting for cgroup to freeze")
)

// ContainerPauser is the runtime pause API, the fallback when the cgroup
// freezer is unavailable. Implemented by the Docker and containerd
// watchers.
type ContainerPauser interface {
	PauseContainer(ctx context.Context, containerID string) error
	UnpauseContainer(ctx context.Context, containerID string) error
}

// Freezer holds containers stopped between their start event and the
// moment enforcement is attached, closing the window in which a job could
// open connections that no filter or DNS redirect covers yet.
//
// It prefers the cgroup v2 freezer (cgroup.freeze) and falls back to the
// runtime pause API. Every freeze is released by an explicit Thaw, by a
// hard-limit timer, or by ThawAll at shutdown; none can outlive the agent
// process short of a crash.
type Freezer struct {
	// Pauser is the optional runtime-API fallback.
	Pauser ContainerPauser
	Logger *slog.Logger

	// HoldLimit overrides the computed hard upper bound on how long a
	// container may stay frozen. Zero means max(timeout, handleStartTimeout)
	// + freezeHoldSlack.
	HoldLimit time.Duration

	// CgroupRoot is the prefix a recovered marker's cgroup path must live
	// under. Empty means /sys/fs/cgroup. A marker pointing elsewhere (or
	// containing "..") is discarded: the state dir is trusted input only up
	// to the point of writing into the filesystem.
	CgroupRoot string

	// StateDir is where freeze markers are persisted before a container is
	// frozen. Empty means DefaultFreezeStateDir. Configurable for tests.
	StateDir string

	// Kill is invoked when a hard limit expires on a freeze whose
	// KillOnExpire flag is set (block mode): a container whose enforcement
	// was never confirmed must not simply be released. Nil means thaw only.
	Kill func(containerID, cgroupPath string)

	mu     sync.Mutex
	active map[*Freeze]struct{}
}

// Freeze is one held container. Thaw is idempotent and safe to call from
// any goroutine.
type Freeze struct {
	f      *Freezer
	id     string
	cgroup string // freeze target; empty for the runtime-pause fallback
	marker string // persisted marker path; removed on Thaw
	thaw   func() error

	// KillOnExpire makes the hard-limit timer kill the container instead of
	// only releasing it. The handler sets it for block-mode policies.
	killOnExpire atomic.Bool
	once         sync.Once
	timer        atomic.Pointer[time.Timer] // set after construction; the timer callback may race the store
}

// Thaw releases the container. It is a no-op after the first call.
func (z *Freeze) Thaw() {
	if z == nil {
		return
	}

	z.once.Do(func() {
		if t := z.timer.Load(); t != nil {
			t.Stop()
		}

		err := z.thaw()
		thawFailed := err != nil && !errors.Is(err, os.ErrNotExist)

		if thawFailed {
			// A cgroup that is already gone (container exited) needs no thaw.
			z.f.Logger.Error("thaw container failed", "container_id", truncID(z.id), "error", err)
		}

		// Keep the marker when the thaw did not take effect, so the next
		// agent start retries it instead of forgetting a frozen container.
		if z.marker != "" && !thawFailed {
			_ = os.Remove(z.marker)
		}

		z.f.mu.Lock()
		delete(z.f.active, z)
		z.f.mu.Unlock()
	})
}

// SetKillOnExpire selects what the hard-limit timer does: kill (true) or
// only release (false). Nil-safe.
func (z *Freeze) SetKillOnExpire(v bool) {
	if z != nil {
		z.killOnExpire.Store(v)
	}
}

// ThawAll releases every container still held. Called on agent shutdown.
func (f *Freezer) ThawAll() {
	f.mu.Lock()
	held := make([]*Freeze, 0, len(f.active))

	for z := range f.active {
		held = append(held, z)
	}
	f.mu.Unlock()

	for _, z := range held {
		z.Thaw()
	}
}

// Freeze stops the container and returns once it is confirmed stopped or
// the timeout expires. cgroupPath is the container's cgroup directory (the
// scope; descendants freeze with it); it may be empty to force the
// runtime-API path.
//
// On any error the container is released before returning, so the caller
// never has to thaw a failed freeze. ErrFreezeUnavailable means nothing
// was frozen and the caller should proceed.
func (f *Freezer) Freeze(ctx context.Context, containerID, cgroupPath string, timeout time.Duration) (*Freeze, error) {
	if timeout <= 0 {
		timeout = DefaultFreezeTimeout
	}

	var (
		thaw   func() error
		err    error
		marker string
		target = cgroupPath
	)

	if cgroupPath != "" {
		marker = f.writeMarker("cgroup", cgroupPath)
		thaw, err = freezeCgroup(ctx, cgroupPath, timeout)

		if err != nil {
			f.removeMarker(marker)
			marker = ""
		}
	} else {
		err = ErrFreezeUnavailable
	}

	if errors.Is(err, ErrFreezeUnavailable) && f.Pauser != nil {
		target = ""

		thaw, marker, err = f.pauseContainerMarked(ctx, containerID)
	}

	if err != nil {
		return nil, err
	}

	z := &Freeze{f: f, id: containerID, cgroup: target, marker: marker, thaw: thaw}

	hold := f.HoldLimit
	if hold <= 0 {
		hold = max(timeout, handleStartTimeout) + freezeHoldSlack
	}

	f.mu.Lock()
	if f.active == nil {
		f.active = make(map[*Freeze]struct{})
	}

	f.active[z] = struct{}{}
	f.mu.Unlock()

	z.timer.Store(time.AfterFunc(hold, func() {
		kill := z.killOnExpire.Load() && f.Kill != nil

		f.Logger.Error("freeze hard limit reached without confirmed enforcement",
			"container_id", truncID(containerID), "hold", hold, "kill", kill)

		if kill {
			f.Kill(containerID, target)
		}

		z.Thaw()
	}))

	return z, nil
}

// FreezePause freezes through the runtime pause API only. Used when the
// cgroup route failed in a way that does not mean the container is gone.
func (f *Freezer) FreezePause(ctx context.Context, containerID string) (*Freeze, error) {
	if f.Pauser == nil {
		return nil, ErrFreezeUnavailable
	}

	thaw, marker, err := f.pauseContainerMarked(ctx, containerID)
	if err != nil {
		return nil, err
	}

	z := &Freeze{f: f, id: containerID, marker: marker, thaw: thaw}

	f.mu.Lock()
	if f.active == nil {
		f.active = make(map[*Freeze]struct{})
	}

	f.active[z] = struct{}{}
	f.mu.Unlock()

	hold := f.HoldLimit
	if hold <= 0 {
		hold = handleStartTimeout + freezeHoldSlack
	}

	z.timer.Store(time.AfterFunc(hold, func() {
		kill := z.killOnExpire.Load() && f.Kill != nil

		f.Logger.Error("pause hard limit reached without confirmed enforcement",
			"container_id", truncID(containerID), "hold", hold, "kill", kill)

		if kill {
			f.Kill(containerID, "")
		}

		z.Thaw()
	}))

	return z, nil
}

func (f *Freezer) stateDir() string {
	if f.StateDir != "" {
		return f.StateDir
	}

	return DefaultFreezeStateDir
}

// writeMarker persists "kind value" before the container is frozen, so a
// restarted agent can release it. Returns the marker path, or "" when the
// marker could not be written (logged: the freeze still proceeds, because
// refusing would turn a /run problem into an outage).
func (f *Freezer) writeMarker(kind, value string) string {
	dir := f.stateDir()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.Logger.Warn("freeze marker dir unavailable; a crash while frozen could not be recovered", "dir", dir, "error", err)

		return ""
	}

	sum := sha256.Sum256([]byte(kind + ":" + value))
	path := filepath.Join(dir, hex.EncodeToString(sum[:]))

	if err := os.WriteFile(path, []byte(kind+" "+value+"\n"), 0o600); err != nil {
		f.Logger.Warn("freeze marker write failed; a crash while frozen could not be recovered", "path", path, "error", err)

		return ""
	}

	return path
}

func (f *Freezer) removeMarker(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// RecoverFrozen releases every container a previous agent process left
// frozen: it reads the persisted markers, thaws each cgroup that still
// exists (or unpauses the container for the runtime fallback), and deletes
// the markers. Call it at startup, before enumerating running containers.
// Returns the number of markers processed.
func (f *Freezer) RecoverFrozen(ctx context.Context) int {
	entries, err := os.ReadDir(f.stateDir())
	if err != nil {
		return 0
	}

	n := 0

	for _, e := range entries {
		path := filepath.Join(f.stateDir(), e.Name())

		b, readErr := os.ReadFile(path)
		_ = os.Remove(path)

		if readErr != nil {
			continue
		}

		kind, value, ok := strings.Cut(strings.TrimSpace(string(b)), " ")
		if !ok || value == "" {
			continue
		}

		n++

		switch kind {
		case "cgroup":
			if !f.validCgroupPath(value) {
				f.Logger.Error("recover: ignoring marker with a cgroup path outside the cgroup mount", "path", value)

				continue
			}

			if werr := writeCgroupFile(filepath.Join(value, "cgroup.freeze"), "0"); werr != nil && !errors.Is(werr, os.ErrNotExist) {
				f.Logger.Error("recover: thaw cgroup failed", "cgroup", value, "error", werr)
			} else {
				f.Logger.Warn("recovered container left frozen by a previous agent process", "cgroup", value)
			}
		case "pause":
			if f.Pauser == nil {
				continue
			}

			uctx, cancel := context.WithTimeout(ctx, thawTimeout)
			uerr := f.Pauser.UnpauseContainer(uctx, value)

			cancel()

			if uerr != nil {
				f.Logger.Warn("recover: unpause failed (container may be gone)", "container_id", truncID(value), "error", uerr)
			} else {
				f.Logger.Warn("recovered container left paused by a previous agent process", "container_id", truncID(value))
			}
		}
	}

	return n
}

// pauseContainerMarked is the runtime-API fallback. The marker is written
// before the pause so a crash between pause and thaw is recoverable.
func (f *Freezer) pauseContainerMarked(ctx context.Context, containerID string) (func() error, string, error) {
	marker := f.writeMarker("pause", containerID)

	err := f.Pauser.PauseContainer(ctx, containerID)
	if err != nil {
		f.removeMarker(marker)

		return nil, "", fmt.Errorf("pause container: %w", err)
	}

	return func() error {
		uctx, cancel := context.WithTimeout(context.Background(), thawTimeout)
		defer cancel()

		return f.Pauser.UnpauseContainer(uctx, containerID)
	}, marker, nil
}

// freezeCgroup writes cgroup.freeze and waits for cgroup.events to report
// frozen. It returns ErrFreezeUnavailable when the interface file does not
// exist but the cgroup does, and an os.ErrNotExist-wrapped error when the
// cgroup itself is gone.
func freezeCgroup(ctx context.Context, cgroupPath string, timeout time.Duration) (func() error, error) {
	freezeFile := filepath.Join(cgroupPath, "cgroup.freeze")
	eventsFile := filepath.Join(cgroupPath, "cgroup.events")

	err := writeCgroupFile(freezeFile, "1")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, statErr := os.Stat(cgroupPath); statErr == nil {
				return nil, fmt.Errorf("%w: no cgroup.freeze in %s", ErrFreezeUnavailable, cgroupPath)
			}
		}

		return nil, fmt.Errorf("write cgroup.freeze: %w", err)
	}

	thaw := func() error {
		return writeCgroupFile(freezeFile, "0")
	}

	deadline := time.Now().Add(timeout)
	wait := freezePollMin

	for {
		frozen, readErr := cgroupFrozen(eventsFile)

		switch {
		case readErr != nil:
			_ = thaw()

			return nil, fmt.Errorf("read cgroup.events: %w", readErr)
		case frozen:
			return thaw, nil
		}

		if time.Now().After(deadline) {
			_ = thaw()

			return nil, fmt.Errorf("%w (%s)", ErrFreezeTimeout, timeout)
		}

		select {
		case <-ctx.Done():
			_ = thaw()

			return nil, fmt.Errorf("freeze interrupted: %w", ctx.Err())
		case <-time.After(wait):
		}

		wait = min(wait*2, freezePollMax)
	}
}

// cgroupFrozen parses the "frozen" key of a cgroup.events file.
func cgroupFrozen(eventsFile string) (bool, error) {
	f, err := os.Open(eventsFile)
	if err != nil {
		return false, err //nolint:wrapcheck // caller wraps with the file name
	}
	defer f.Close() //nolint:errcheck // read-only

	sc := bufio.NewScanner(f)

	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "frozen "); ok {
			return strings.TrimSpace(v) == "1", nil
		}
	}

	return false, sc.Err() //nolint:wrapcheck // caller wraps with the file name
}

// writeCgroupFile writes to an existing cgroup interface file. It never
// creates the file: on a non-cgroup directory (or a kernel without the
// interface) a create would either fail confusingly or leave a stray file.
func writeCgroupFile(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err //nolint:wrapcheck // callers inspect os.ErrNotExist
	}

	_, werr := f.WriteString(value)
	cerr := f.Close()

	if werr != nil {
		return werr //nolint:wrapcheck // surfaced with context by callers
	}

	return cerr //nolint:wrapcheck // surfaced with context by callers
}

func (f *Freezer) validCgroupPath(p string) bool {
	root := f.CgroupRoot
	if root == "" {
		root = cgroupMount
	}

	return filepath.IsAbs(p) && !strings.Contains(p, "..") && strings.HasPrefix(filepath.Clean(p), strings.TrimRight(root, "/")+"/")
}
