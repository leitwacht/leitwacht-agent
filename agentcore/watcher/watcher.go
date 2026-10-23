//go:build linux

package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	// DefaultEventBuffer is the default buffer size for the container event
	// channel. CE exposes LEITWACHT_CE_EVENT_BUFFER for tuning under
	// burst-heavy CI loads; the default is sized for a single node's
	// legitimate peak.
	DefaultEventBuffer = 64
	// maxBackoff is the maximum backoff duration between reconnection attempts.
	maxBackoff = 30 * time.Second
)

// Watcher monitors the Docker/Podman API for container lifecycle events.
type Watcher struct {
	client *client.Client
	logger *slog.Logger
	scope  Scope // CE-only: maps a container label / env to a policy scope
	ch     chan ContainerEvent
}

// SetScope configures the optional scope mapping. CE wires this from
// LEITWACHT_CE_SCOPE_LABEL / SCOPE_ENV; EE leaves it unset and falls
// back to CI_PROJECT_PATH. Safe to call once at startup before Watch().
func (w *Watcher) SetScope(s Scope) { w.scope = s }

// New creates a Watcher connected to the given container socket. If
// socketPath is empty, it uses the default Docker socket. Pass
// DefaultEventBuffer for buffer if you have no specific tuning need.
func New(socketPath string, buffer int, logger *slog.Logger) (*Watcher, error) {
	if buffer < 1 {
		buffer = DefaultEventBuffer
	}

	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if socketPath != "" {
		opts = append(opts, client.WithHost("unix://"+socketPath))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}

	return &Watcher{
		client: cli,
		logger: logger,
		ch:     make(chan ContainerEvent, buffer),
	}, nil
}

// ChannelDepth returns the current backlog length of the event channel.
func (w *Watcher) ChannelDepth() int { return len(w.ch) }

// Watch starts watching for container events and sends ContainerEvents on the returned channel.
// It reconnects on stream errors with exponential backoff.
func (w *Watcher) Watch(ctx context.Context) <-chan ContainerEvent {
	ch := w.ch

	go func() {
		defer close(ch)

		backoff := time.Second

		for {
			w.logger.Info("starting container event stream")

			start := time.Now()

			w.streamEvents(ctx, ch)

			select {
			case <-ctx.Done():
				return
			default:
			}

			// Reset backoff if stream was healthy for >1 minute.
			if time.Since(start) > time.Minute {
				backoff = time.Second
			}

			w.logger.Warn("event stream disconnected, reconnecting", "backoff", backoff)

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			backoff = min(backoff*2, maxBackoff)
		}
	}()

	return ch
}

func (w *Watcher) streamEvents(ctx context.Context, ch chan<- ContainerEvent) {
	f := filters.NewArgs()
	f.Add("type", string(events.ContainerEventType))
	f.Add("event", "start")
	f.Add("event", "die")
	f.Add("label", labelManaged+"=true")

	eventCh, errCh := w.client.Events(ctx, events.ListOptions{Filters: f})

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err != nil {
				w.logger.Error("event stream error", "error", err)
			}

			return
		case ev := <-eventCh:
			w.handleEvent(ctx, ev, ch)
		}
	}
}

func (w *Watcher) handleEvent(ctx context.Context, ev events.Message, ch chan<- ContainerEvent) {
	action := string(ev.Action)
	containerID := ev.Actor.ID

	if action == "die" {
		select {
		case ch <- ContainerEvent{
			Action:      "die",
			ContainerID: containerID,
			Labels:      ev.Actor.Attributes,
			JobID:       ev.Actor.Attributes[labelPrefix+"job.id"],
			PipelineID:  ev.Actor.Attributes[labelPrefix+"pipeline.id"],
		}:
		case <-ctx.Done():
		}

		return
	}

	info, err := w.client.ContainerInspect(ctx, containerID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			w.logger.Debug("container gone before inspect", "container_id", truncID(containerID))

			return
		}

		w.logger.Error("inspect container", "container_id", truncID(containerID), "error", err)

		return
	}

	mounts := extractMountPaths(info.Mounts)

	event := extractContainerEvent(
		"start",
		containerID,
		info.Config.Labels,
		info.Config.Env,
		mounts,
		info.HostConfig.Runtime,
		info.State.Pid,
		"", // Docker: cgroup path resolved from PID at attach time
		w.scope,
	)
	if event == nil {
		w.logger.Debug("skipping non-build container", "container_id", truncID(containerID))

		return
	}

	w.logger.Info("build container detected",
		"container_id", truncID(containerID),
		"project", event.ProjectPath,
		"job_id", event.JobID,
	)

	select {
	case ch <- *event:
	case <-ctx.Done():
	}
}

func extractMountPaths(mounts []container.MountPoint) []string {
	paths := make([]string, len(mounts))
	for i, m := range mounts {
		paths[i] = m.Source
	}

	return paths
}

// RecoverRunning enumerates already-running managed build containers.
func (w *Watcher) RecoverRunning(ctx context.Context) ([]ContainerEvent, error) {
	f := filters.NewArgs()
	f.Add("label", labelManaged+"=true")
	f.Add("status", "running")

	containers, err := w.client.ContainerList(ctx, container.ListOptions{Filters: f})
	if err != nil {
		return nil, fmt.Errorf("list running containers: %w", err)
	}

	var evts []ContainerEvent

	for _, c := range containers {
		info, err := w.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			w.logger.Warn("inspect running container", "container_id", truncID(c.ID), "error", err)

			continue
		}

		mounts := extractMountPaths(info.Mounts)

		event := extractContainerEvent(
			"start",
			c.ID,
			info.Config.Labels,
			info.Config.Env,
			mounts,
			info.HostConfig.Runtime,
			info.State.Pid,
			"", // Docker: cgroup path resolved from PID at attach time
			w.scope,
		)
		if event != nil {
			evts = append(evts, *event)
		}
	}

	return evts, nil
}

// KillContainer kills a container with SIGKILL.
func (w *Watcher) KillContainer(ctx context.Context, containerID string) error {
	err := w.client.ContainerKill(ctx, containerID, "KILL")
	if err != nil {
		return fmt.Errorf("kill container %s: %w", containerID, err)
	}

	return nil
}

// Runtime identifies this watcher as the Docker-API one. Podman served
// through its Docker-compatible socket is configured as the "docker"
// runtime and takes this path too; it is the only runtime whose containers
// the handler freezes before attach.
func (w *Watcher) Runtime() string { return RuntimeDocker }

// PauseContainer freezes every process in the container via the runtime's
// pause API. Fallback for hosts where the cgroup v2 freezer is not usable.
func (w *Watcher) PauseContainer(ctx context.Context, containerID string) error {
	err := w.client.ContainerPause(ctx, containerID)
	if err != nil {
		return fmt.Errorf("pause container %s: %w", truncID(containerID), err)
	}

	return nil
}

// UnpauseContainer reverses PauseContainer.
func (w *Watcher) UnpauseContainer(ctx context.Context, containerID string) error {
	err := w.client.ContainerUnpause(ctx, containerID)
	if err != nil {
		return fmt.Errorf("unpause container %s: %w", truncID(containerID), err)
	}

	return nil
}

// Close releases the Docker client connection.
func (w *Watcher) Close() error {
	return w.client.Close() //nolint:wrapcheck // pass through Docker client errors
}
