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
}

// NewInotifyCgroupSource constructs an event source bound to the
// supplied paths. Pass an empty slice to disable the join layer
// gracefully (Run reports ErrCgroupJoinUnsupported).
func NewInotifyCgroupSource(paths []string) *InotifyCgroupSource {
	return &InotifyCgroupSource{WatchPaths: paths}
}

// Run blocks until ctx is cancelled, the inotify fd is closed, or a
// fatal error fires. Per-event errors are logged by the joiner — the
// source's contract is just to surface filesystem events as they
// arrive.
func (s *InotifyCgroupSource) Run(ctx context.Context, creates chan<- CgroupCreateEvent, removes chan<- CgroupRemoveEvent) error {
	defer close(creates)
	defer close(removes)

	if len(s.WatchPaths) == 0 {
		return ErrCgroupJoinUnsupported
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify init: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	wd2path := make(map[int32]string)

	var mu sync.Mutex

	addWatch := func(path string) error {
		wd, addErr := unix.InotifyAddWatch(fd, path, unix.IN_CREATE|unix.IN_DELETE|unix.IN_ONLYDIR)
		if addErr != nil {
			return fmt.Errorf("inotify add %s: %w", path, addErr)
		}

		mu.Lock()
		wd2path[int32(wd)] = path
		mu.Unlock()

		return nil
	}

	for _, p := range s.WatchPaths {
		if err := addWatch(p); err != nil {
			return err
		}
	}

	// Cancellation: close the inotify fd from a side goroutine
	// when ctx fires. The read in the main loop unblocks with EBADF
	// and we return ctx.Err().
	go func() {
		<-ctx.Done()
		_ = unix.Close(fd)
	}()

	buf := make([]byte, 64*1024)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				// Non-blocking mode without epoll integration is
				// unusual; if we hit EAGAIN, wait briefly via the
				// poll loop. In practice the fd is blocking once
				// we're in Read, so this branch is just defensive.
				continue
			}

			// EBADF / EINTR after ctx.Done means cancellation.
			if ctx.Err() != nil {
				return ctx.Err()
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

			mu.Lock()
			parent := wd2path[raw.Wd]
			mu.Unlock()

			if parent != "" && name != "" {
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

			offset += unix.SizeofInotifyEvent + nameLen
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
