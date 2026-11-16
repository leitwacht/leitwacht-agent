//go:build linux

package watcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
)

// findPodContainerTimeout bounds one FindPodContainerPID lookup.
const findPodContainerTimeout = 5 * time.Second

var dns1123Re = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

var (
	// ErrPodContainerNotFound: no running container matches. This is the
	// normal state on nodes without the container; consumers should wrap
	// it as enforcer.ErrTrustedPIDAbsent so the proxy polls less often.
	ErrPodContainerNotFound = errors.New("no running container matches")
	// ErrPodContainerConfig: the namespace or container name is invalid.
	// A configuration error, not an absent container.
	ErrPodContainerConfig = errors.New("invalid pod container selector")
	// ErrPodContainerAmbiguous: more than one running container matches
	// (for example two replicas); the caller must not guess.
	ErrPodContainerAmbiguous = errors.New("more than one running container matches")
	// ErrPodContainerCgroup: the task's cgroup does not belong to the pod
	// UID its labels claim.
	ErrPodContainerCgroup = errors.New("task cgroup does not match the container's pod UID")
)

// podContainer is one containerd container with its task state.
type podContainer struct {
	ID      string
	Labels  map[string]string
	Running bool
	PID     int
}

// listPodContainers is the containerd seam: the containers of the given
// containerd namespace with their task's state.
type listPodContainers func(ctx context.Context) ([]podContainer, error)

// FindPodContainerPID returns the host PID of the running task of the
// container named containerName in the Kubernetes namespace podNamespace,
// and its pod UID. Containers are matched on the container labels the CRI
// sets from kubelet data (io.kubernetes.pod.namespace,
// io.kubernetes.container.name); sandbox (pause) containers and pod
// labels, which a workload can influence, are never consulted. A CI job
// cannot create a container in that namespace without Kubernetes API
// rights there.
//
// As defense in depth the task's /proc/<pid>/cgroup must contain the pod
// UID. Several running matches yield ErrPodContainerAmbiguous. Consumers
// feeding enforcer.BuildDNSConfig.TrustedPID should wrap
// ErrPodContainerNotFound (normal on nodes without the container) as
// enforcer.ErrTrustedPIDAbsent to get the long poll backoff. addr is the
// containerd socket and containerdNS its namespace (normally "k8s.io").
func FindPodContainerPID(
	ctx context.Context, addr, containerdNS, podNamespace, containerName string,
) (pid int, podUID string, err error) {
	ctx, cancel := context.WithTimeout(ctx, findPodContainerTimeout)
	defer cancel()

	// The values end up in a containerd filter expression: only DNS-1123
	// names (which Kubernetes requires anyway) are accepted.
	if !dns1123Re.MatchString(podNamespace) || !dns1123Re.MatchString(containerName) {
		return 0, "", fmt.Errorf("%w: pod namespace and container name must be DNS-1123 names", ErrPodContainerConfig)
	}

	filter := fmt.Sprintf(`labels."io.kubernetes.pod.namespace"==%q,labels."io.kubernetes.container.name"==%q`,
		podNamespace, containerName)

	list := func(ctx context.Context) ([]podContainer, error) {
		return listContainerdContainers(ctx, addr, containerdNS, filter)
	}

	return findPodContainerPID(ctx, list, "/proc", podNamespace, containerName)
}

func findPodContainerPID(
	ctx context.Context, list listPodContainers, procRoot, podNamespace, containerName string,
) (pid int, podUID string, err error) {
	if podNamespace == "" || containerName == "" {
		return 0, "", fmt.Errorf("%w: pod namespace and container name are required", ErrPodContainerConfig)
	}

	cs, err := list(ctx)
	if err != nil {
		return 0, "", err
	}

	var match *podContainer

	for i := range cs {
		c := &cs[i]
		if c.Labels["io.cri-containerd.kind"] == "sandbox" ||
			c.Labels["io.kubernetes.pod.namespace"] != podNamespace ||
			c.Labels["io.kubernetes.container.name"] != containerName ||
			!c.Running || c.PID <= 0 {
			continue
		}

		if match != nil {
			return 0, "", fmt.Errorf("%w: %s/%s", ErrPodContainerAmbiguous, podNamespace, containerName)
		}

		match = c
	}

	if match == nil {
		return 0, "", fmt.Errorf("%w: %s/%s", ErrPodContainerNotFound, podNamespace, containerName)
	}

	uid := match.Labels["io.kubernetes.pod.uid"]
	if uid == "" {
		return 0, "", fmt.Errorf("%w: container has no pod UID label", ErrPodContainerCgroup)
	}

	cg, err := os.ReadFile(filepath.Join(procRoot, fmt.Sprint(match.PID), "cgroup")) //nolint:gosec // procfs
	if err != nil {
		return 0, "", fmt.Errorf("read task cgroup: %w", err)
	}

	if !strings.Contains(string(cg), uid) && !strings.Contains(string(cg), strings.ReplaceAll(uid, "-", "_")) {
		return 0, "", ErrPodContainerCgroup
	}

	return match.PID, uid, nil
}

func listContainerdContainers(ctx context.Context, addr, ns, filter string) ([]podContainer, error) {
	cli, err := containerd.New(addr, containerd.WithDefaultNamespace(ns))
	if err != nil {
		return nil, fmt.Errorf("connect to containerd at %s: %w", addr, err)
	}

	defer func() { _ = cli.Close() }()

	cs, err := cli.Containers(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list containerd containers: %w", err)
	}

	var out []podContainer

	for _, c := range cs {
		info, ierr := c.Info(ctx, containerd.WithoutRefreshedMetadata)
		if ierr != nil {
			continue
		}

		pc := podContainer{ID: c.ID(), Labels: info.Labels}

		if task, terr := c.Task(ctx, nil); terr == nil {
			if st, serr := task.Status(ctx); serr == nil && st.Status == containerd.Running {
				pc.Running = true
				pc.PID = int(task.Pid())
			}
		}

		out = append(out, pc)
	}

	return out, nil
}
