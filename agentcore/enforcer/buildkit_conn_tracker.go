package enforcer

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// BuildKitConnTracker records the agent's own established gRPC connection
// to buildkitd (its local and remote addresses). The daemon-ancestry guard
// uses it to find which local buildkitd is on the other end of THAT
// connection, which a pod cannot fake by listening on the same port.
type BuildKitConnTracker struct {
	mu      sync.Mutex
	conns   map[string]*trackedEntry // by local address string, refcounted
	current *trackedEntry
	gen     atomic.Uint64
}

type trackedEntry struct {
	local, remote net.Addr
	n             int
}

// NewBuildKitConnTracker returns an empty tracker.
func NewBuildKitConnTracker() *BuildKitConnTracker {
	return &BuildKitConnTracker{conns: map[string]*trackedEntry{}}
}

func (t *BuildKitConnTracker) set(local, remote net.Addr) {
	t.mu.Lock()

	if t.conns == nil {
		t.conns = map[string]*trackedEntry{}
	}

	e := t.conns[local.String()]
	if e == nil {
		e = &trackedEntry{local: local, remote: remote}
		t.conns[local.String()] = e
	}

	e.n++
	t.current = e
	t.mu.Unlock()
	t.gen.Add(1)
}

// clear releases one reference to the connection with this local address.
// A stale close never wipes a newer connection.
func (t *BuildKitConnTracker) clear(local net.Addr) {
	t.mu.Lock()

	if e := t.conns[local.String()]; e != nil {
		if e.n--; e.n <= 0 {
			delete(t.conns, local.String())

			if t.current == e {
				t.current = nil

				for _, o := range t.conns {
					t.current = o
				}
			}
		}
	}

	t.mu.Unlock()
	t.gen.Add(1)
}

// Local returns the agent-side address of the current connection.
func (t *BuildKitConnTracker) Local() (net.Addr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.current == nil {
		return nil, false
	}

	return t.current.local, true
}

// Generation changes on every connect and disconnect.
func (t *BuildKitConnTracker) Generation() uint64 { return t.gen.Load() }

type trackedConn struct {
	net.Conn
	t    *BuildKitConnTracker
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.t.clear(c.LocalAddr()) })

	return c.Conn.Close() //nolint:wrapcheck // passthrough
}

// WithConnTracker records the watcher's established connection (production
// dial path only; ignored when custom dial options are set).
func WithConnTracker(t *BuildKitConnTracker) WatcherOption {
	return func(w *AttributionWatcher) { w.tracker = t }
}

func dialNetwork(addr string) string {
	if strings.HasPrefix(addr, "unix:") {
		return "unix"
	}

	return "tcp"
}
