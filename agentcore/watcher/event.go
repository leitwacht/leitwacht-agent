// Package watcher provides container lifecycle event monitoring.
package watcher

// ContainerEvent represents a lifecycle event for a GitLab Runner managed container.
type ContainerEvent struct {
	Action      string            // "start", "die", "sibling_start", "pod_sandbox_start", "pod_sandbox_die"
	ContainerID string            // full container ID (sandbox container ID for pod_sandbox_* actions)
	Labels      map[string]string // all container labels
	ProjectPath string            // from CI_PROJECT_PATH env var
	JobID       string            // from label com.gitlab.gitlab-runner.job.id
	PipelineID  string            // from label com.gitlab.gitlab-runner.pipeline.id
	JobURL      string            // from label com.gitlab.gitlab-runner.job.url
	GitRef      string            // from label com.gitlab.gitlab-runner.job.ref
	JobName     string            // from CI_JOB_NAME env var
	JobStage    string            // from CI_JOB_STAGE env var
	PipelineSrc string            // from CI_PIPELINE_SOURCE env var
	PID         int               // container PID (from inspect)
	CgroupPath  string            // absolute cgroup path (containerd: from OCI spec, Docker: empty = resolve from PID)
	PodUID      string            // K8s pod UID from io.kubernetes.pod.uid (set on pod_sandbox_* actions; for SandboxChanged keying)

	// Security flags detected during inspection
	HasDinD              bool // DOCKER_HOST=tcp://... in env
	HasSocketMount       bool // /var/run/docker.sock in mounts
	HasGVisor            bool // runtime == "runsc"
	MissingNetworkPerBld bool // FF_NETWORK_PER_BUILD not set or false
}

const (
	labelPrefix  = "com.gitlab.gitlab-runner."
	labelManaged = labelPrefix + "managed"
)
