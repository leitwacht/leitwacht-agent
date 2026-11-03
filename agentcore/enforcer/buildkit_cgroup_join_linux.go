//go:build linux

package enforcer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// InotifyCgroupSource watches one or more cgroup-parent directories
// for child cgroup creates/removes via inotify. Each parent is
// expected to be a directory that BuildKit's executor populates
// with runc container IDs as subdirectories — see
// docs/BUILDKIT_STEP_ATTRIBUTION.md for the layouts in the
// supported BuildKit deployment modes.
//
// Inotify (vs fanotify): inotify is simpler, has wider kernel
// version support (since 2.6), and the buildkit cgroup layout is
// flat — we don't need recursive watches.
type InotifyCgroupSource struct {
	// WatchPaths is the list of cgroup-parent directories. Empty
	// means "nothing to watch"; Run returns ErrCgroupJoinUnsupported
	// in that case so operators see a loud config issue.
	WatchPaths []string

	// ScanExisting, when set, reports every directory already present
	// under each watch path as a create once the initial watches are
	// in place. Use it for sources started after the cgroup parent
	// already exists (lazy activation, restarts) so children created
	// before the watch existed are still seen by the joiner. Leave it
	// unset for a cold agent start, where pre-existing children
	// belong to in-flight builds the fresh registry cannot match.
	ScanExisting bool

	// rewatchEvery overrides rewatchInterval. Test-only.
	rewatchEvery time.Duration
}

// NewInotifyCgroupSource constructs an event source bound to the
// supplied paths. Pass an empty slice to disable the join layer
// gracefully (Run reports ErrCgroupJoinUnsupported).
func NewInotifyCgroupSource(paths []string) *InotifyCgroupSource {
	return &InotifyCgroupSource{WatchPaths: paths}
}

// rewatchInterval is how often a watch that was lost (watched dir
// deleted or its filesystem unmounted) is retried.
const rewatchInterval = 2 * time.Second

// Run blocks until ctx is cancelled or a fatal error fires. Per-event
// errors are logged by the joiner — the source's contract is just to
// surface filesystem events as they arrive.
//
// The loop blocks in poll(2) on the (non-blocking) inotify fd plus an
// eventfd that a helper goroutine signals on ctx cancellation, so an
// idle queue costs no CPU. Both fds are closed exactly once, after the
// helper has been joined, on every return path.
//
//nolint:gocognit,cyclop,funlen // single poll/read/dispatch loop reads cleanly top-to-bottom
func (s *InotifyCgroupSource) Run(ctx context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) (retErr error) {
	defer close(creates)
	defer close(removes)

	if len(s.WatchPaths) == 0 {
		return ErrCgroupJoinUnsupported
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify init: %w", err)
	}

	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(fd)

		return fmt.Errorf("eventfd: %w", err)
	}

	done := make(chan struct{})

	var helper sync.WaitGroup

	helper.Add(1)

	go func() {
		defer helper.Done()

		select {
		case <-ctx.Done():
			one := []byte{1, 0, 0, 0, 0, 0, 0, 0}
			_, _ = unix.Write(efd, one)
		case <-done:
		}
	}()

	defer func() {
		close(done)
		helper.Wait()
		_ = unix.Close(fd)
		_ = unix.Close(efd)
	}()

	wd2path := make(map[int32]string)
	lost := make(map[string]struct{}) // paths whose watch must be re-established

	addWatch := func(path string) error {
		wd, addErr := unix.InotifyAddWatch(fd, path, unix.IN_CREATE|unix.IN_DELETE|unix.IN_ONLYDIR)
		if addErr != nil {
			return fmt.Errorf("inotify add %s: %w", path, addErr)
		}

		wd2path[int32(wd)] = path

		return nil
	}

	for _, p := range s.WatchPaths {
		if err := addWatch(p); err != nil {
			return err
		}
	}

	// emitExisting reports every directory currently under path as a
	// create. Used after an event-queue overflow and after re-watching,
	// to cover events the kernel did not deliver.
	emitExisting := func(path string) error {
		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return nil //nolint:nilerr // dir vanished again; the lost-watch path handles it
		}

		for _, e := range entries {
			if !e.IsDir() {
				continue
			}

			select {
			case creates <- CgroupCreateEvent{ContainerID: e.Name(), CgroupPath: filepath.Join(path, e.Name())}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		return nil
	}

	if s.ScanExisting {
		for _, p := range s.WatchPaths {
			if err := emitExisting(p); err != nil {
				return err
			}
		}
	}

	retryLost := func() error {
		for path := range lost {
			if addErr := addWatch(path); addErr != nil {
				continue
			}

			delete(lost, path)

			if err := emitExisting(path); err != nil {
				return err
			}
		}

		return nil
	}

	rewatch := rewatchInterval
	if s.rewatchEvery > 0 {
		rewatch = s.rewatchEvery
	}

	pollFds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
		{Fd: int32(efd), Events: unix.POLLIN},
	}
	buf := make([]byte, 64*1024)

	for {
		timeout := -1
		if len(lost) > 0 {
			timeout = int(rewatch / time.Millisecond)
		}

		_, pollErr := unix.Poll(pollFds, timeout)
		if pollErr != nil {
			if errors.Is(pollErr, unix.EINTR) {
				continue
			}

			return fmt.Errorf("inotify poll: %w", pollErr)
		}

		if pollFds[1].Revents != 0 {
			return ctx.Err()
		}

		if len(lost) > 0 {
			if err := retryLost(); err != nil {
				return err
			}
		}

		if pollFds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("inotify fd failed")
		}

		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		// Drain the queue until it would block.
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) {
					break
				}

				if errors.Is(err, unix.EINTR) {
					continue
				}

				return fmt.Errorf("inotify read: %w", err)
			}

			offset := 0

			for offset+unix.SizeofInotifyEvent <= n {
				raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
				nameLen := int(raw.Len)

				var name string

				if nameLen > 0 {
					nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+nameLen]
					// Names are NUL-padded; trim.
					name = strings.TrimRight(string(nameBytes), "\x00")
				}

				offset += unix.SizeofInotifyEvent + nameLen

				switch {
				case raw.Mask&unix.IN_Q_OVERFLOW != 0:
					// Events were dropped: re-list every watched dir.
					for _, p := range wd2path {
						if err := emitExisting(p); err != nil {
							return err
						}
					}

					continue
				case raw.Mask&unix.IN_IGNORED != 0:
					// The watch is gone (dir removed or fs unmounted).
					if p, ok := wd2path[raw.Wd]; ok {
						delete(wd2path, raw.Wd)

						lost[p] = struct{}{}
					}

					if err := retryLost(); err != nil {
						return err
					}

					continue
				}

				parent := wd2path[raw.Wd]
				if parent == "" || name == "" {
					continue
				}

				path := filepath.Join(parent, name)

				switch {
				case raw.Mask&unix.IN_CREATE != 0 && raw.Mask&unix.IN_ISDIR != 0:
					select {
					case creates <- CgroupCreateEvent{ContainerID: name, CgroupPath: path}:
					case <-ctx.Done():
						return ctx.Err()
					}
				case raw.Mask&unix.IN_DELETE != 0 && raw.Mask&unix.IN_ISDIR != 0:
					select {
					case removes <- CgroupRemoveEvent{ContainerID: name, CgroupPath: path}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
		}
	}
}

// cgroupInode returns the inode number of path. Cgroup v2 uses the
// inode of the cgroup directory as the kernel cgroup_id — the same
// value eBPF helpers like bpf_get_current_cgroup_id() return for a
// process in that cgroup. Matching on this id is how Phase 3
// enrichment ties egress events back to a build vertex.
func cgroupInode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}

	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: unexpected sys type %T", path, fi.Sys())
	}

	return sys.Ino, nil
}

//nolint:gochecknoinits // platform-specific stat-fn binding; init is the right shape.
func init() {
	defaultStatFn = cgroupInode
}
