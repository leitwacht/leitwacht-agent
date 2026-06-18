//go:build linux

package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	eventtypes "github.com/containerd/containerd/api/events"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/internal/idutil"
)

// ContainerdWatcher monitors the containerd API for container lifecycle events.
// Used in K8S environments where containers are managed by containerd via CRI.
type ContainerdWatcher struct {
	client        *containerd.Client
	logger        *slog.Logger
	podNamespaces map[string]bool // K8S namespace filter for runner pods (empty = no filtering)

	// sandboxIDs tracks pause-container IDs for which we emitted pod_sandbox_start.
	// On the corresponding TaskExit we look up here so we can emit pod_sandbox_die
	// (instead of the generic die) and unwind pod-level eBPF attach.
	sandboxMu  sync.Mutex
	sandboxIDs map[string]string // sandbox container ID → pod UID

	scope Scope // CE-only: maps a container label / env to a policy scope
	ch    chan ContainerEvent
}

// SetScope configures the optional scope mapping. CE wires this from
// LEITWACHT_CE_SCOPE_LABEL / SCOPE_ENV; EE leaves it unset and falls
// back to CI_PROJECT_PATH. Safe to call once at startup before Watch().
func (w *ContainerdWatcher) SetScope(s Scope) { w.scope = s }

// NewContainerd creates a ContainerdWatcher connected to the given containerd socket.
// podNamespaces filters containers to the given K8S namespaces (e.g., "gitlab-runner,gitlab-runner-staging").
// Only containers with `io.kubernetes.pod.namespace` matching one of these values are inspected.
// If empty, all containers are inspected. Comma-separated values are split automatically.
func NewContainerd(address, namespace, podNamespaces string, buffer int, logger *slog.Logger) (*ContainerdWatcher, error) {
	if buffer < 1 {
		buffer = DefaultEventBuffer
	}

	cli, err := containerd.New(address, containerd.WithDefaultNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("connect to containerd at %s: %w", address, err)
	}

	w := &ContainerdWatcher{
		client: cli,
		logger: logger,
		ch:     make(chan ContainerEvent, buffer),
	}

	if podNamespaces != "" {
		w.podNamespaces = make(map[string]bool)
		for _, ns := range strings.Split(podNamespaces, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				w.podNamespaces[ns] = true
			}
		}
		names := make([]string, 0, len(w.podNamespaces))
		for ns := range w.podNamespaces {
			names = append(names, ns)
		}
		slices.Sort(names)
		logger.Info("containerd pod namespace filter", "namespaces", strings.Join(names, ","))
	}

	return w, nil
}

// ChannelDepth returns the current backlog length of the event channel.
func (w *ContainerdWatcher) ChannelDepth() int { return len(w.ch) }

// Watch starts watching for container task events and sends ContainerEvents on the returned channel.
func (w *ContainerdWatcher) Watch(ctx context.Context) <-chan ContainerEvent {
	ch := w.ch

	go func() {
		defer close(ch)

		backoff := time.Second

		for {
			w.logger.Info("starting containerd event stream")

			start := time.Now()

			w.streamEvents(ctx, ch)

			select {
			case <-ctx.Done():
				return
			default:
			}

			if time.Since(start) > time.Minute {
				backoff = time.Second
			}

			w.logger.Warn("containerd event stream disconnected, reconnecting", "backoff", backoff)

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

func (w *ContainerdWatcher) streamEvents(ctx context.Context, ch chan<- ContainerEvent) {
	eventCh, errCh := w.client.Subscribe(ctx,
		`topic=="/tasks/start"`,
		`topic=="/tasks/exit"`,
	)

	w.logger.Info("containerd event subscription active")

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err != nil {
				w.logger.Error("containerd event stream error", "error", err)
			}

			return
		case envelope := <-eventCh:
			w.logger.Debug("containerd event received", "topic", envelope.Topic, "namespace", envelope.Namespace)
			w.handleEnvelope(ctx, envelope, ch)
		}
	}
}

func (w *ContainerdWatcher) handleEnvelope(ctx context.Context, envelope *events.Envelope, ch chan<- ContainerEvent) {
	evt, err := typeurl.UnmarshalAny(envelope.Event)
	if err != nil {
		w.logger.Warn("unmarshal containerd event", "error", err)

		return
	}

	switch e := evt.(type) {
	case *eventtypes.TaskStart:
		w.logger.Info("task start event", "container_id", truncID(e.ContainerID), "pid", e.Pid)
		w.handleTaskStart(ctx, e.ContainerID, e.Pid, ch)
	case *eventtypes.TaskExit:
		// Containerd emits /tasks/exit for every exec session that exits, not
		// just the container's main task. The two are distinguished by the ID
		// field: for the main task ID == ContainerID, for an exec ID is the
		// exec session ID. The K8s GitLab runner drives builds via repeated
		// execs into a long-lived container, so without this filter the first
		// `script` step exiting tears down enforcement and everything after
		// (git clone, package installs, build) runs unobserved. See
		// containerd's own CRI server for the same workaround:
		// internal/cri/server/events.go — "Use ID instead of ContainerID to
		// rule out TaskExit event for exec."
		if e.ID != e.ContainerID {
			w.logger.Debug("task exec exit event ignored",
				"container_id", truncID(e.ContainerID),
				"exec_id", e.ID,
			)

			return
		}

		w.logger.Debug("task exit event", "container_id", truncID(e.ContainerID))

		// Sandbox exits go through pod_sandbox_die so the enforcer can
		// detach pod-level eBPF. Real-container exits go through the
		// generic die path as today.
		if podUID, isSandbox := w.consumeSandbox(e.ContainerID); isSandbox {
			select {
			case ch <- ContainerEvent{
				Action:      "pod_sandbox_die",
				ContainerID: e.ContainerID,
				PodUID:      podUID,
			}:
			case <-ctx.Done():
			}

			return
		}

		select {
		case ch <- ContainerEvent{
			Action:      "die",
			ContainerID: e.ContainerID,
		}:
		case <-ctx.Done():
		}
	default:
		w.logger.Warn("unexpected containerd event type", "type", fmt.Sprintf("%T", evt))
	}
}

//nolint:funlen // sibling_start emission adds to an already sequential handler
func (w *ContainerdWatcher) handleTaskStart(ctx context.Context, containerID string, pid uint32, ch chan<- ContainerEvent) {
	container, err := w.client.LoadContainer(ctx, containerID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			w.logger.Debug("container gone before inspect", "container_id", truncID(containerID))

			return
		}

		w.logger.Error("load containerd container", "container_id", truncID(containerID), "error", err)

		return
	}

	info, err := container.Info(ctx)
	if err != nil {
		w.logger.Error("inspect containerd container", "container_id", truncID(containerID), "error", err)

		return
	}

	// Sandbox (pause) containers in the runner namespace drive pod-level
	// eBPF attach: derive the pod cgroup from the sandbox cgroup and attach
	// once at the parent slice. Every container that joins the pod (init,
	// helper, build) is then filtered automatically — no per-container attach
	// race for the build container's first packets.
	if info.Labels["io.cri-containerd.kind"] == "sandbox" {
		w.handleSandboxStart(ctx, container, info, containerID, pid, ch)

		return
	}

	if !w.isRunnerContainer(info.Labels) {
		w.logger.Debug("skipping non-runner container", "container_id", truncID(containerID),
			"pod_namespace", info.Labels["io.kubernetes.pod.namespace"],
			"pod_name", info.Labels["io.kubernetes.pod.name"])

		return
	}

	w.logger.Info("runner container detected", "container_id", truncID(containerID),
		"pod_name", info.Labels["io.kubernetes.pod.name"])

	spec, err := container.Spec(ctx)
	if err != nil {
		w.logger.Error("get container spec", "container_id", truncID(containerID), "error", err)

		return
	}

	var env []string
	if spec.Process != nil {
		env = spec.Process.Env
	}

	var mounts []string
	for _, m := range spec.Mounts {
		mounts = append(mounts, m.Source)
	}

	// Extract cgroup path from OCI spec (avoids cgroup namespace issues).
	var cgroupPath string
	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		cgroupPath = "/sys/fs/cgroup" + spec.Linux.CgroupsPath
	}

	event := extractContainerEvent(
		"start",
		containerID,
		info.Labels,
		env,
		mounts,
		info.Runtime.Name,
		int(pid),
		cgroupPath,
		w.scope,
	)
	if event == nil {
		// No CI_PROJECT_PATH — this is a sibling container (helper, svc-N).
		// Emit a sibling_start event so the agent can set up netns-level DNS
		// infrastructure before the build container starts.
		w.logger.Info("sibling container detected (no CI_PROJECT_PATH)",
			"container_id", truncID(containerID),
			"pod_name", info.Labels["io.kubernetes.pod.name"],
		)

		select {
		case ch <- ContainerEvent{
			Action:      "sibling_start",
			ContainerID: containerID,
			Labels:      info.Labels,
			PID:         int(pid),
			CgroupPath:  cgroupPath,
		}:
		case <-ctx.Done():
		}

		return
	}

	w.logger.Info("build container detected",
		"container_id", truncID(containerID),
		"project", event.ProjectPath,
		"job_id", event.JobID,
		"cgroup", cgroupPath,
	)

	select {
	case ch <- *event:
	case <-ctx.Done():
	}
}

// RecoverRunning enumerates already-running managed build and sibling containers.
//
//nolint:funlen // sibling_start emission adds to an already sequential scan
func (w *ContainerdWatcher) RecoverRunning(ctx context.Context) ([]ContainerEvent, error) {
	containers, err := w.client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containerd containers: %w", err)
	}

	var (
		evts      []ContainerEvent
		sandboxes int
		nonRunner int
		noTask    int
		noBuild   int
	)

	w.logger.Info("recovery: scanning containerd containers", "total", len(containers))

	for _, c := range containers {
		info, err := c.Info(ctx)
		if err != nil {
			w.logger.Warn("inspect container during recovery", "container_id", truncID(c.ID()), "error", err)

			continue
		}

		if info.Labels["io.cri-containerd.kind"] == "sandbox" {
			sandboxes++

			if ev, ok := w.recoverSandbox(ctx, c, info); ok {
				evts = append(evts, ev)
			}

			continue
		}

		if !w.isRunnerContainer(info.Labels) {
			nonRunner++

			continue
		}

		task, err := c.Task(ctx, nil)
		if err != nil {
			noTask++

			continue
		}

		status, err := task.Status(ctx)
		if err != nil || status.Status != containerd.Running {
			noTask++

			continue
		}

		spec, err := c.Spec(ctx)
		if err != nil {
			w.logger.Warn("get spec during recovery", "container_id", truncID(c.ID()), "error", err)

			continue
		}

		var env []string
		if spec.Process != nil {
			env = spec.Process.Env
		}

		var mounts []string
		for _, m := range spec.Mounts {
			mounts = append(mounts, m.Source)
		}

		var cgroupPath string
		if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
			cgroupPath = "/sys/fs/cgroup" + spec.Linux.CgroupsPath
		}

		event := extractContainerEvent(
			"start",
			c.ID(),
			info.Labels,
			env,
			mounts,
			info.Runtime.Name,
			int(task.Pid()),
			cgroupPath,
			w.scope,
		)
		if event != nil {
			evts = append(evts, *event)
		} else {
			// Sibling container (helper/svc) — emit so netns infra can be set up.
			evts = append(evts, ContainerEvent{
				Action:      "sibling_start",
				ContainerID: c.ID(),
				Labels:      info.Labels,
				PID:         int(task.Pid()),
				CgroupPath:  cgroupPath,
			})
			noBuild++
		}
	}

	w.logger.Info("recovery: scan complete",
		"total", len(containers),
		"sandboxes", sandboxes,
		"non_runner", nonRunner,
		"no_task", noTask,
		"no_build", noBuild,
		"recovered", len(evts),
	)

	return evts, nil
}

// RunningContainerIDs returns the set of container IDs that currently have a
// Running task in the watched namespace. Used by the agent's reconcile loop to
// detect containers whose /tasks/exit event was missed — dropped under event-
// stream backpressure or a `--rm` teardown race — so an attached container
// absent from this set has stopped and its enforcer must be detached (and its
// final report flushed). Best-effort: a listing error is returned so the caller
// skips the tick rather than detaching everything on a transient failure.
func (w *ContainerdWatcher) RunningContainerIDs(ctx context.Context) (map[string]struct{}, error) {
	containers, err := w.client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containerd containers: %w", err)
	}

	running := make(map[string]struct{}, len(containers))

	for _, c := range containers {
		task, err := c.Task(ctx, nil)
		if err != nil {
			continue // no task → not running
		}

		status, err := task.Status(ctx)
		if err != nil || status.Status != containerd.Running {
			continue
		}

		running[c.ID()] = struct{}{}
	}

	return running, nil
}

// KillContainer kills a container with SIGKILL.
func (w *ContainerdWatcher) KillContainer(ctx context.Context, containerID string) error {
	task, err := w.getTask(ctx, containerID)
	if err != nil {
		return err
	}

	return task.Kill(ctx, syscall.SIGKILL) //nolint:wrapcheck // pass through containerd errors
}

func (w *ContainerdWatcher) getTask(ctx context.Context, containerID string) (containerd.Task, error) {
	container, err := w.client.LoadContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("load container %s: %w", truncID(containerID), err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get task for %s: %w", truncID(containerID), err)
	}

	return task, nil
}

// handleSandboxStart emits a pod_sandbox_start event for a runner-namespace
// pause container. Extracted from handleTaskStart so the caller's nesting
// stays under the lint threshold; non-runner sandboxes are dropped silently.
func (w *ContainerdWatcher) handleSandboxStart(
	ctx context.Context,
	container containerd.Container,
	info containers.Container,
	containerID string,
	pid uint32,
	ch chan<- ContainerEvent,
) {
	if !w.isRunnerContainer(info.Labels) {
		w.logger.Debug("skipping non-runner sandbox", "container_id", truncID(containerID),
			"pod_namespace", info.Labels["io.kubernetes.pod.namespace"])

		return
	}

	spec, err := container.Spec(ctx)
	if err != nil {
		w.logger.Warn("get sandbox spec", "container_id", truncID(containerID), "error", err)

		return
	}

	var cgroupPath string
	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		cgroupPath = "/sys/fs/cgroup" + spec.Linux.CgroupsPath
	}

	podUID := info.Labels["io.kubernetes.pod.uid"]
	w.rememberSandbox(containerID, podUID)
	w.logger.Info("pod sandbox detected", "container_id", truncID(containerID),
		"pod_uid", podUID, "pod_name", info.Labels["io.kubernetes.pod.name"])

	select {
	case ch <- ContainerEvent{
		Action:      "pod_sandbox_start",
		ContainerID: containerID,
		Labels:      info.Labels,
		PID:         int(pid),
		CgroupPath:  cgroupPath,
		PodUID:      podUID,
	}:
	case <-ctx.Done():
	}
}

// recoverSandbox builds a pod_sandbox_start event for an already-running
// runner-namespace pause container during agent restart. Returns
// (event, true) if a recoverable event was produced, (zero, false)
// otherwise (non-runner namespace, no task, task not running, or spec
// fetch failed). Extracted from RecoverRunning to keep its cognitive
// complexity under the lint threshold.
func (w *ContainerdWatcher) recoverSandbox(
	ctx context.Context,
	c containerd.Container,
	info containers.Container,
) (ContainerEvent, bool) {
	if !w.isRunnerContainer(info.Labels) {
		return ContainerEvent{}, false
	}

	task, err := c.Task(ctx, nil)
	if err != nil {
		return ContainerEvent{}, false
	}

	status, err := task.Status(ctx)
	if err != nil || status.Status != containerd.Running {
		return ContainerEvent{}, false
	}

	spec, err := c.Spec(ctx)
	if err != nil {
		w.logger.Warn("get sandbox spec during recovery", "container_id", truncID(c.ID()), "error", err)

		return ContainerEvent{}, false
	}

	var cgroupPath string
	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		cgroupPath = "/sys/fs/cgroup" + spec.Linux.CgroupsPath
	}

	podUID := info.Labels["io.kubernetes.pod.uid"]
	w.rememberSandbox(c.ID(), podUID)

	return ContainerEvent{
		Action:      "pod_sandbox_start",
		ContainerID: c.ID(),
		Labels:      info.Labels,
		PID:         int(task.Pid()),
		CgroupPath:  cgroupPath,
		PodUID:      podUID,
	}, true
}

// rememberSandbox records that containerID is a pod sandbox we've emitted
// pod_sandbox_start for, so the corresponding TaskExit can be routed to
// pod_sandbox_die.
func (w *ContainerdWatcher) rememberSandbox(containerID, podUID string) {
	w.sandboxMu.Lock()
	defer w.sandboxMu.Unlock()

	if w.sandboxIDs == nil {
		w.sandboxIDs = make(map[string]string)
	}

	w.sandboxIDs[containerID] = podUID
}

// consumeSandbox removes containerID from the sandbox set and returns
// (podUID, true) if it was present, or ("", false) otherwise.
func (w *ContainerdWatcher) consumeSandbox(containerID string) (string, bool) {
	w.sandboxMu.Lock()
	defer w.sandboxMu.Unlock()

	podUID, ok := w.sandboxIDs[containerID]
	if ok {
		delete(w.sandboxIDs, containerID)
	}

	return podUID, ok
}

// isRunnerContainer checks if the container belongs to the configured runner pod namespace.
// Returns true if no namespace filter is configured (all containers pass).
func (w *ContainerdWatcher) isRunnerContainer(labels map[string]string) bool {
	if w.podNamespaces == nil {
		return true
	}

	return w.podNamespaces[labels["io.kubernetes.pod.namespace"]]
}

// Close releases the containerd client connection.
func (w *ContainerdWatcher) Close() error {
	return w.client.Close() //nolint:wrapcheck // pass through containerd client errors
}

// truncID is the package-local alias for idutil.Trunc.
var truncID = idutil.Trunc
