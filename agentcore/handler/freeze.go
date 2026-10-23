package handler

import (
	"bufio"
	"context"
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

	mu     sync.Mutex
	active map[*Freeze]struct{}
}

// Freeze is one held container. Thaw is idempotent and safe to call from
// any goroutine.
type Freeze struct {
	f     *Freezer
	id    string
	thaw  func() error
	once  sync.Once
	timer atomic.Pointer[time.Timer] // set after construction; the timer callback may race the store
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
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			// A cgroup that is already gone (container exited) needs no thaw.
			z.f.Logger.Error("thaw container failed", "container_id", truncID(z.id), "error", err)
		}

		z.f.mu.Lock()
		delete(z.f.active, z)
		z.f.mu.Unlock()
	})
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
		thaw func() error
		err  error
	)

	if cgroupPath != "" {
		thaw, err = freezeCgroup(ctx, cgroupPath, timeout)
	} else {
		err = ErrFreezeUnavailable
	}

	if errors.Is(err, ErrFreezeUnavailable) && f.Pauser != nil {
		thaw, err = f.pauseContainer(ctx, containerID)
	}

	if err != nil {
		return nil, err
	}

	z := &Freeze{f: f, id: containerID, thaw: thaw}

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
		f.Logger.Error("freeze hard limit reached, thawing container without enforcement confirmed",
			"container_id", truncID(containerID), "hold", hold)
		z.Thaw()
	}))

	return z, nil
}

// pauseContainer is the runtime-API fallback.
func (f *Freezer) pauseContainer(ctx context.Context, containerID string) (func() error, error) {
	err := f.Pauser.PauseContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("pause container: %w", err)
	}

	return func() error {
		uctx, cancel := context.WithTimeout(context.Background(), thawTimeout)
		defer cancel()

		return f.Pauser.UnpauseContainer(uctx, containerID)
	}, nil
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
