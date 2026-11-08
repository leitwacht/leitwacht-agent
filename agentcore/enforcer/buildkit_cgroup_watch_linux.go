//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// inotifyDirWatcher is the Linux CgroupDirWatcher. It signals on child
// creation/move-in and on the watched directory itself disappearing;
// the resolver does the actual (idempotent) re-resolve.
type inotifyDirWatcher struct {
	f      *os.File
	fd     int
	events chan struct{}

	mu     sync.Mutex
	byPath map[string]int
	byWD   map[int]string
	closed bool
}

const cgroupWatchMask = unix.IN_CREATE | unix.IN_MOVED_TO | unix.IN_DELETE_SELF |
	unix.IN_MOVE_SELF | unix.IN_ONLYDIR

func newPlatformDirWatcher() (CgroupDirWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify init: %w", err)
	}

	w := &inotifyDirWatcher{
		// Non-blocking fd: os.File reads go through the runtime
		// poller, so Close unblocks the reader.
		f:      os.NewFile(uintptr(fd), "cgroup-dir-inotify"),
		fd:     fd,
		events: make(chan struct{}, 1),
		byPath: make(map[string]int),
		byWD:   make(map[int]string),
	}

	go w.readLoop()

	return w, nil
}

func (w *inotifyDirWatcher) Events() <-chan struct{} { return w.events }

func (w *inotifyDirWatcher) signal() {
	select {
	case w.events <- struct{}{}:
	default:
	}
}

func (w *inotifyDirWatcher) Watch(dirs []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("watcher closed")
	}

	want := make(map[string]struct{}, len(dirs))
	for _, d := range dirs {
		want[d] = struct{}{}
	}

	for path, wd := range w.byPath {
		if _, keep := want[path]; !keep {
			_, _ = unix.InotifyRmWatch(w.fd, uint32(wd)) //nolint:gosec // wd is a small positive kernel id
			delete(w.byPath, path)
			delete(w.byWD, wd)
		}
	}

	var firstErr error

	for _, d := range dirs {
		if _, have := w.byPath[d]; have {
			continue
		}

		wd, err := unix.InotifyAddWatch(w.fd, d, cgroupWatchMask)
		if err != nil {
			if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) && firstErr == nil {
				firstErr = fmt.Errorf("inotify add %s: %w", d, err)
			}

			continue
		}

		// Inotify returns the existing wd for an already-watched inode.
		if old, dup := w.byWD[wd]; dup && old != d {
			delete(w.byPath, old)
		}

		w.byPath[d] = wd
		w.byWD[wd] = d
	}

	return firstErr
}

func (w *inotifyDirWatcher) readLoop() {
	buf := make([]byte, 16*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))

	// Closing events tells the resolver the watcher is gone (it
	// then logs and polls only); a deliberate Close ends the resolver
	// anyway.
	defer close(w.events)

	for {
		n, err := w.f.Read(buf)
		if err != nil || n <= 0 {
			return
		}

		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			wd, mask, nameLen := parseInotifyHeader(buf[off:])

			if mask&unix.IN_IGNORED != 0 {
				w.mu.Lock()
				if p, ok := w.byWD[wd]; ok {
					delete(w.byWD, wd)
					delete(w.byPath, p)
				}
				w.mu.Unlock()
			}

			off += unix.SizeofInotifyEvent + nameLen
		}

		w.signal()
	}
}

func (w *inotifyDirWatcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()

		return nil
	}

	w.closed = true
	w.mu.Unlock()

	return w.f.Close()
}

// parseInotifyHeader decodes struct inotify_event's wd, mask and len
// (native endianness; the name is not needed).
func parseInotifyHeader(b []byte) (wd int, mask uint32, nameLen int) {
	e := binary.NativeEndian

	return int(int32(e.Uint32(b[0:4]))), e.Uint32(b[4:8]), int(e.Uint32(b[12:16]))
}
