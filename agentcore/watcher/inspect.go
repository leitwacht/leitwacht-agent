package watcher

import (
	"slices"
	"strings"
)

// Scope tells the watcher how to map a container to a CE policy scope.
// When Label is set and the container has that label, its value is used
// as ProjectPath in preference to CI_PROJECT_PATH; if the label is
// absent, Env is consulted next; otherwise CI_PROJECT_PATH wins. EE
// leaves Scope zero — its policy lookup keys directly off
// CI_PROJECT_PATH and the scope plumbing is irrelevant there.
type Scope struct {
	Label string
	Env   string
}

// extractContainerEvent builds a ContainerEvent from container inspection data.
// Returns nil if the container is not a build container (no scope match
// and no CI_PROJECT_PATH).
//
//nolint:unparam // action and cgroupPath are general-purpose params; today's
func extractContainerEvent(
	action string,
	containerID string,
	labels map[string]string,
	env []string,
	mounts []string,
	runtime string,
	pid int,
	cgroupPath string,
	scope Scope,
) *ContainerEvent {
	envMap := parseEnv(env)

	projectPath := resolveScope(scope, labels, envMap)
	if projectPath == "" {
		return nil // not a build container (helper or service)
	}

	ev := &ContainerEvent{
		Action:      action,
		ContainerID: containerID,
		Labels:      labels,
		ProjectPath: projectPath,
		JobID:       labelOrEnv(labels, labelPrefix+"job.id", envMap, "CI_JOB_ID"),
		PipelineID:  labelOrEnv(labels, labelPrefix+"pipeline.id", envMap, "CI_PIPELINE_ID"),
		JobURL:      labelOrEnv(labels, labelPrefix+"job.url", envMap, "CI_JOB_URL"),
		GitRef:      labelOrEnv(labels, labelPrefix+"job.ref", envMap, "CI_COMMIT_REF_NAME"),
		JobName:     envMap["CI_JOB_NAME"],
		JobStage:    envMap["CI_JOB_STAGE"],
		PipelineSrc: envMap["CI_PIPELINE_SOURCE"],
		PID:         pid,
		CgroupPath:  cgroupPath,
	}

	// DinD detection
	if dockerHost := envMap["DOCKER_HOST"]; strings.HasPrefix(dockerHost, "tcp://") {
		ev.HasDinD = true
	}

	// Socket mount detection
	if slices.Contains(mounts, "/var/run/docker.sock") {
		ev.HasSocketMount = true
	}

	// gVisor detection
	if runtime == "runsc" {
		ev.HasGVisor = true
	}

	// FF_NETWORK_PER_BUILD detection
	ffVal := envMap["FF_NETWORK_PER_BUILD"]
	if ffVal == "" || strings.EqualFold(ffVal, "false") || ffVal == "0" {
		ev.MissingNetworkPerBld = true
	}

	// Honeypot mount detection — check for expected honeypot target paths.
	ev.MissingHoneypotMounts = !hasHoneypotMounts(mounts)

	return ev
}

// honeypotTargets are mount target paths that indicate honeypot files are present.
var honeypotTargets = []string{ //nolint:gochecknoglobals // constant-like lookup table
	"/.aws/credentials",
	"/.ssh/id_rsa",
	"/.config/gcloud/application_default_credentials.json",
}

func hasHoneypotMounts(mounts []string) bool {
	for _, m := range mounts {
		for _, target := range honeypotTargets {
			if strings.HasSuffix(m, target) {
				return true
			}
		}
	}

	return false
}

// resolveScope returns the project/scope key for a container, preferring
// (in order): a CE-configured pod label, a CE-configured env var, and
// finally CI_PROJECT_PATH. Returns "" when none match — callers treat
// that as "not a build container".
func resolveScope(scope Scope, labels, envMap map[string]string) string {
	if scope.Label != "" {
		if v := labels[scope.Label]; v != "" {
			return v
		}
	}
	if scope.Env != "" {
		if v := envMap[scope.Env]; v != "" {
			return v
		}
	}
	return envMap["CI_PROJECT_PATH"]
}

// labelOrEnv returns the label value if present, otherwise falls back to the env var.
// This allows extractContainerEvent to work with both Docker labels (bare metal)
// and env-only metadata (containerd/K8S where GitLab labels don't exist).
func labelOrEnv(labels map[string]string, labelKey string, env map[string]string, envKey string) string {
	if v := labels[labelKey]; v != "" {
		return v
	}

	return env[envKey]
}

func parseEnv(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}

	return m
}
