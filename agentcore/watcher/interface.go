package watcher

import "context"

// ContainerWatcher abstracts the Docker/Podman container lifecycle API.
// The production implementation uses the Docker client (requires a running daemon).
// Tests inject a fake to verify event handling without Docker.
type ContainerWatcher interface {
	// Watch returns a channel of container lifecycle events.
	// Reconnects automatically on stream errors.
	Watch(ctx context.Context) <-chan ContainerEvent

	// RecoverRunning returns events for containers that are already running.
	RecoverRunning(ctx context.Context) ([]ContainerEvent, error)

	// KillContainer sends SIGKILL to a container.
	KillContainer(ctx context.Context, containerID string) error

	// ChannelDepth returns the current depth of the event channel
	// (len(ch)). Used by metric exporters to detect back-pressure
	// against containerd / docker subscriptions.
	ChannelDepth() int

	// Close releases the underlying client connection.
	Close() error
}

// Runtime names returned by RuntimeNamer.
const (
	// RuntimeDocker covers the Docker API and Podman's Docker-compatible API.
	RuntimeDocker = "docker"
	// RuntimeContainerd covers containerd/CRI (Kubernetes).
	RuntimeContainerd = "containerd"
)

// RuntimeNamer is implemented by watchers that identify their runtime. The
// handler uses it to decide, explicitly, whether the pre-attach freeze
// applies (Docker/Podman only).
type RuntimeNamer interface {
	Runtime() string
}
