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
	mu     sync.Mutex
	local  net.Addr
	remote net.Addr
	gen    atomic.Uint64
}

// NewBuildKitConnTracker returns an empty tracker.
func NewBuildKitConnTracker() *BuildKitConnTracker { return &BuildKitConnTracker{} }

func (t *BuildKitConnTracker) set(local, remote net.Addr) {
	t.mu.Lock()
	t.local, t.remote = local, remote
	t.mu.Unlock()
	t.gen.Add(1)
}

// clear forgets the connection if it is still the one given (a stale
// close must not wipe a newer connection).
func (t *BuildKitConnTracker) clear(local net.Addr) {
	t.mu.Lock()

	if t.local == local {
		t.local, t.remote = nil, nil
	}

	t.mu.Unlock()
	t.gen.Add(1)
}

// Local returns the agent-side address of the current connection.
func (t *BuildKitConnTracker) Local() (net.Addr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.local, t.local != nil
}

// Generation changes on every connect and disconnect.
func (t *BuildKitConnTracker) Generation() uint64 { return t.gen.Load() }

type trackedConn struct {
	net.Conn
	t *BuildKitConnTracker
}

func (c *trackedConn) Close() error {
	c.t.clear(c.LocalAddr())

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
