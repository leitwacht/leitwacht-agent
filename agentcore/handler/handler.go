// Package handler processes container lifecycle events from the watcher,
// pauses each container, fetches its policy, runs security checks, attaches
// enforcement, and reports back. Edition-neutral: EE wires it with gRPC
// sinks, CE wires it with stdout/Prometheus/webhook sinks. The handler
// itself never imports either edition's wire format.
package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/internal/idutil"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/violation"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/watcher"
)

const (
	// handleStartTimeout bounds the pause-to-unpause window. If enforcement
	// cannot be set up within this time (e.g., backend unreachable), the
	// container is unpaused to avoid indefinite freezes that would trigger
	// kubelet liveness probe failures or pod deadline expiry.
	handleStartTimeout = 10 * time.Second
)

// truncID is the package-local alias for idutil.Trunc.
var truncID = idutil.Trunc

// infoFromEvent projects the identity-bearing fields of a watcher event
// onto the enforcer's ContainerInfo. The two structs intentionally stay
// separate (one is the watcher's input shape, the other the enforcer's
// retained-for-reporting shape) — the projection lives here so adding a
// new identity field is a one-line edit instead of a multi-site sweep.
func infoFromEvent(ev watcher.ContainerEvent) enforcer.ContainerInfo {
	return enforcer.ContainerInfo{
		ContainerID:      ev.ContainerID,
		ProjectPath:      ev.ProjectPath,
		JobID:            ev.JobID,
		PipelineID:       ev.PipelineID,
		JobURL:           ev.JobURL,
		GitRef:           ev.GitRef,
		JobName:          ev.JobName,
		JobStage:         ev.JobStage,
		PipelineSrc:      ev.PipelineSrc,
		CgroupPath:       ev.CgroupPath,
		AllowProcMemRead: ev.Labels["leitwacht.io/allow-proc-read"] == "true",
		AllowCredWatch:   ev.Labels["leitwacht.io/allow-cred-read"] == "true",
	}
}

// UnknownProjectMode controls what happens when GetPolicy returns an
// error or no entry. Two stances:
//
//   - UnknownEnforce: synthesise a policy with Enrolled=true and the
//     daemon's DefaultAction. The full security gauntlet runs; the
//     enforcer attaches and applies the default action's rules. This
//     is "fail closed" for operators who want every container caught
//     by the rule fixture or rejected.
//
//   - UnknownPass: synthesise an unenrolled policy. The handler takes
//     the passive-only path: DNS interception attaches so the
//     CI-job's leitwacht-init init container exits, but no security
//     checks run, no advisories fire, no rules are matched. This is
//     "fail open" for operators whose rule fixture intentionally
//     omits projects that should be ignored entirely.
//
// Pick UnknownEnforce when an unmapped scope means "default-deny";
// pick UnknownPass when it means "out of scope, leave it alone."
type UnknownProjectMode int

const (
	// UnknownEnforce treats unknown projects as enrolled with DefaultAction.
	UnknownEnforce UnknownProjectMode = iota
	// UnknownPass treats unknown projects as unenrolled (passive-only).
	UnknownPass
)

// String returns the env-var-friendly form of the mode for logging.
func (m UnknownProjectMode) String() string {
	if m == UnknownPass {
		return "pass"
	}

	return "enforce"
}

// Handler processes container lifecycle events.
type Handler struct {
	Watcher            watcher.ContainerWatcher
	Policy             policy.Provider
	Enforcer           *enforcer.Manager
	ViolationSink      violation.Sink
	AdvisorySink       advisory.Sink
	Logger             *slog.Logger
	DefaultAction      string
	UnknownProjectMode UnknownProjectMode
}

// HandleStart processes a container start event: pauses the container to
// prevent egress before enforcement is ready, fetches policy, runs security
// checks, attaches enforcement, then unpauses.
//
//nolint:funlen // orchestration handler with sequential security steps
func (h *Handler) HandleStart(ctx context.Context, ev watcher.ContainerEvent) {
	// Bound the entire pause-to-unpause window to prevent indefinite container freezes.
	ctx, cancel := context.WithTimeout(ctx, handleStartTimeout)
	defer cancel()

	h.Logger.Info("handling container start",
		"container_id", truncID(ev.ContainerID),
		"project", ev.ProjectPath,
		"job_id", ev.JobID,
	)

	// On K8s the build container's eBPF cgroup attach race is closed by
	// the pod-sandbox attach path (HandlePodSandboxStart →
	// Manager.AttachPodSandbox): when the pause container's /tasks/start
	// fires — strictly before any user container in the pod runs — the
	// agent derives the parent pod cgroup and attaches the cgroup_skb
	// program once at that level. Every container that subsequently joins
	// the pod (init, helper, build) is filtered automatically; the build
	// container's first packet hits an already-attached program. The
	// per-container AttachCgroup call below is skipped when the
	// NetnsContext is podAttached, and stays as the fallback path for
	// Docker/Podman/plain-containerd shapes that have no pod cgroup.

	pol, err := h.Policy.GetPolicy(ctx, ev.ProjectPath)
	if err != nil {
		// UnknownProjectMode controls the fallback. Default
		// (UnknownEnforce) preserves the legacy "fail-closed" stance —
		// synthesise a policy carrying DefaultAction so the gauntlet
		// runs. UnknownPass drops Enrolled so the passive-only branch
		// below picks it up: DNS attaches but no rules run.
		h.Logger.Info("policy lookup failed; applying unknown-project fallback",
			"project", ev.ProjectPath,
			"mode", h.UnknownProjectMode,
			"error", err,
		)
		pol = &policy.ResolvedPolicy{
			ProjectPath: ev.ProjectPath,
			Action:      h.DefaultAction,
			Enrolled:    h.UnknownProjectMode == UnknownEnforce,
		}
		pol.BuildLookups()
	}

	// passiveOnly means the project opted out of enforcement. We still
	// attach DNS interception with a no-rule audit-pass policy so the
	// leitwacht-init init container in the CI job pod sees
	// _leitwacht.attached.local resolve to the pinned attachment IP and
	// exits, letting the main container start. Without this branch, the
	// init container times out for every non-enrolled project's CI job
	// and CI breaks completely. Rule matching is a no-op; the security
	// advisory gauntlet (DinD / socket mount / FF_NETWORK_PER_BUILD) is
	// skipped too — projects that opted out shouldn't generate advisories.
	passiveOnly := !pol.Enrolled
	if passiveOnly {
		h.Logger.Debug("non-enrolled project, attaching passive-only",
			"container_id", truncID(ev.ContainerID),
			"project", ev.ProjectPath,
		)

		pol = &policy.ResolvedPolicy{
			ProjectPath: ev.ProjectPath,
			Action:      policy.ActionAudit,
			Enrolled:    true, // locally true so the downstream attach runs
			RuleSets:    map[string][]policy.Rule{"": nil},
		}
		pol.BuildLookups()
	} else {
		// Resolve per-job policy view (action override + per-job baseline domains).
		// Returns a new policy — never mutates the cached original.
		pol = pol.ForJob(ev.JobName)
	}

	report := func(kind advisory.Kind, msg, action string) {
		_ = h.AdvisorySink.ReportAdvisory(ctx, &advisory.Advisory{
			ContainerID:  ev.ContainerID,
			ProjectPath:  ev.ProjectPath,
			JobID:        ev.JobID,
			JobURL:       ev.JobURL,
			Kind:         kind,
			Message:      msg,
			ActionTaken:  action,
			PolicyAction: pol.Action,
		})
	}

	// gVisor — skip enforcement entirely (eBPF can't attach, DNS
	// interception unavailable). leitwacht-init init containers on gVisor
	// runners will also time out; operators must exclude gVisor runners
	// from the leitwacht pod_spec patch.
	if ev.HasGVisor {
		h.Logger.Warn("gVisor container detected, skipping enforcement", "container_id", truncID(ev.ContainerID))

		if !passiveOnly {
			report(advisory.KindGVisorUnsupported,
				"gVisor container detected — eBPF enforcement not possible.\n\n"+
					"Fix: gVisor intercepts syscalls in userspace, preventing eBPF from attaching. "+
					"Use a standard runc runtime for this runner, or exclude gVisor projects from enforcement.",
				"skipped")
		}

		return
	}

	// Non-enrolled projects get DNS interception only — no security
	// advisories, no container kills. Skip straight to attach.
	if passiveOnly {
		h.attachSentinelOnly(ctx, ev, pol)

		return
	}

	// DinD — block mode kills, audit mode warns.
	if ev.HasDinD {
		if pol.Action == policy.ActionBlock {
			h.Logger.Error("DinD detected in block mode, killing container", "container_id", truncID(ev.ContainerID))
			_ = h.Watcher.KillContainer(ctx, ev.ContainerID)

			report(advisory.KindDinDDetected,
				"Docker-in-Docker detected — container killed (block mode).\n\n"+
					"Fix: Replace DinD with kaniko, buildah, or Docker socket binding for image builds. "+
					"DinD spawns nested containers whose network traffic cannot be enforced.",
				"killed")

			return
		}

		h.Logger.Warn("DinD detected in audit mode", "container_id", truncID(ev.ContainerID))

		report(advisory.KindDinDDetected,
			"Docker-in-Docker detected — enforcement cannot cover DinD service container network activity.\n\n"+
				"Fix: Replace DinD with kaniko, buildah, or Docker socket binding for image builds. "+
				"DinD spawns nested containers whose network traffic cannot be enforced.",
			"warned")
	}

	// Socket mount — block mode kills, audit mode warns.
	if ev.HasSocketMount {
		if pol.Action == policy.ActionBlock {
			h.Logger.Error("Docker socket mount in block mode, killing container", "container_id", truncID(ev.ContainerID))
			_ = h.Watcher.KillContainer(ctx, ev.ContainerID)

			report(advisory.KindSocketMount,
				"Docker socket bind mount detected — container killed (block mode).\n\n"+
					"Fix: Remove the /var/run/docker.sock volume mount from the runner's volume configuration "+
					"(config.toml [runners.docker] volumes, or Helm values runners.config volumes). "+
					"Socket access allows spawning sibling containers that bypass network enforcement.",
				"killed")

			return
		}

		h.Logger.Warn("Docker socket mount detected in audit mode", "container_id", truncID(ev.ContainerID))

		report(advisory.KindSocketMount,
			"Docker socket bind mount detected — sibling containers bypass enforcement.\n\n"+
				"Fix: Remove the /var/run/docker.sock volume mount from the runner's volume configuration "+
				"(config.toml [runners.docker] volumes, or Helm values runners.config volumes). "+
				"Socket access allows spawning sibling containers that bypass network enforcement.",
			"warned")
	}

	// FF_NETWORK_PER_BUILD missing — block mode kills, audit mode warns.
	if ev.MissingNetworkPerBld {
		if pol.Action == policy.ActionBlock {
			h.Logger.Error("FF_NETWORK_PER_BUILD missing in block mode, killing container", "container_id", truncID(ev.ContainerID))
			_ = h.Watcher.KillContainer(ctx, ev.ContainerID)

			report(advisory.KindFFNetworkPerBuildMissing,
				"FF_NETWORK_PER_BUILD not enabled — container killed (block mode).\n\n"+
					"Fix: Set FF_NETWORK_PER_BUILD = \"true\" in the runner's environment variables "+
					"(config.toml [[runners.environment]], Helm values runners.config environment, or as a CI/CD variable in GitLab). "+
					"This isolates each job's network stack.",
				"killed")

			return
		}

		h.Logger.Warn("FF_NETWORK_PER_BUILD not set", "container_id", truncID(ev.ContainerID))

		report(advisory.KindFFNetworkPerBuildMissing,
			"FF_NETWORK_PER_BUILD not enabled — cross-job network relay possible.\n\n"+
				"Fix: Set FF_NETWORK_PER_BUILD = \"true\" in the runner's environment variables "+
				"(config.toml [[runners.environment]], Helm values runners.config environment, or as a CI/CD variable in GitLab). "+
				"This isolates each job's network stack.",
			"warned")
	}

	_, attachErr := h.Enforcer.Attach(ctx, infoFromEvent(ev), ev.PID, pol)
	if attachErr != nil {
		// Short-lived helper containers (e.g. GitLab Runner init containers) may exit
		// before we can attach. Don't fire an advisory for these — the build container
		// will start momentarily and attach successfully.
		if errors.Is(attachErr, os.ErrNotExist) {
			h.Logger.Debug("container exited before attach, skipping advisory", "container_id", truncID(ev.ContainerID))
		} else {
			h.Logger.Error("attach enforcement failed", "container_id", truncID(ev.ContainerID), "error", attachErr)
			report(advisory.KindAttachFailure,
				fmt.Sprintf("eBPF enforcement failed to attach: %s\n\n"+
					"Fix: Ensure the host kernel supports eBPF (a maintained kernel current on its distro's security stream), the agent has CAP_SYS_ADMIN/CAP_BPF, "+
					"and the container PID namespace is accessible. Check agent logs for details.", attachErr),
				"warned")
		}
	}
}

// attachSentinelOnly attaches DNS interception with a no-rule audit-pass
// policy so the leitwacht-init init container in a non-enrolled project's
// CI pod exits. No security checks run and no advisories are emitted —
// an opted-out project should not generate pressure on operators.
func (h *Handler) attachSentinelOnly(ctx context.Context, ev watcher.ContainerEvent, pol *policy.ResolvedPolicy) {
	_, err := h.Enforcer.Attach(ctx, infoFromEvent(ev), ev.PID, pol)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		h.Logger.Warn("passive-only attach failed",
			"container_id", truncID(ev.ContainerID),
			"project", ev.ProjectPath,
			"error", err,
		)
	}
}

// HandlePodSandboxStart processes a K8s pause-container /tasks/start event.
// Drives pod-level eBPF cgroup_skb attach: derives the parent pod cgroup
// from the sandbox's cgroup and attaches once for the whole pod, before any
// user container in the pod runs. Falls back silently to per-container
// attach (in HandleStart) when the cgroup path doesn't match a recognised
// K8s shape — the cgroup-shape discriminator is the only K8s-vs-other
// distinction in the enforcer; no runtime field is added.
func (h *Handler) HandlePodSandboxStart(_ context.Context, ev watcher.ContainerEvent) {
	h.Logger.Info("pod sandbox start",
		"sandbox_id", truncID(ev.ContainerID),
		"pod_uid", ev.PodUID,
		"pod_name", ev.Labels["io.kubernetes.pod.name"],
	)

	//nolint:contextcheck // initNetnsContext outlives the per-event context; uses context.Background internally
	err := h.Enforcer.AttachPodSandbox(enforcer.PodSandboxInfo{
		PodUID:     ev.PodUID,
		SandboxID:  ev.ContainerID,
		PID:        ev.PID,
		CgroupPath: ev.CgroupPath,
	})
	if err != nil {
		h.Logger.Warn("attach pod sandbox failed",
			"sandbox_id", truncID(ev.ContainerID),
			"pod_uid", ev.PodUID,
			"error", err,
		)
	}
}

// HandlePodSandboxDie processes a K8s pause-container TaskExit. Releases
// the pod-level eBPF attach (or decrements refcount toward grace-period
// teardown) so kernel objects don't outlive the pod.
func (h *Handler) HandlePodSandboxDie(_ context.Context, ev watcher.ContainerEvent) {
	h.Logger.Debug("pod sandbox die",
		"sandbox_id", truncID(ev.ContainerID),
		"pod_uid", ev.PodUID,
	)

	h.Enforcer.DetachPodSandbox(ev.PodUID, ev.ContainerID)
}

// HandleSiblingStart processes a sibling container start event (e.g., K8s
// helper container). Sets up netns-level DNS infrastructure (proxy, nftables,
// eBPF) so DNS queries are captured before the build container starts.
// No pause, no policy fetch — runs in audit-all mode until the build container
// joins and provides the real policy.
func (h *Handler) HandleSiblingStart(_ context.Context, ev watcher.ContainerEvent) {
	h.Logger.Info("sibling container start",
		"container_id", truncID(ev.ContainerID),
		"pod_name", ev.Labels["io.kubernetes.pod.name"],
	)

	//nolint:contextcheck // context.Background() intentional — outlives caller
	err := h.Enforcer.PrepareNetns(ev.ContainerID, ev.PID, ev.CgroupPath)
	if err != nil {
		h.Logger.Warn("prepare netns for sibling failed",
			"container_id", truncID(ev.ContainerID), "error", err)
	}
}

// HandleDie processes a container die event: detaches enforcement and reports.
func (h *Handler) HandleDie(ctx context.Context, ev watcher.ContainerEvent) {
	result := h.Enforcer.Detach(ev.ContainerID)
	if result == nil {
		return
	}

	// Suppress reports for sibling containers (helper/svc) — they have no
	// project attribution. Their DNS activity is already in the shared netns
	// recorder and will be included in the build container's report.
	if result.Info.ProjectPath == "" {
		h.Logger.Debug("sibling detached, suppressing report",
			"container_id", truncID(ev.ContainerID))

		return
	}

	// ReportAsync persists the stats synchronously (durability floor —
	// a crash after return is covered by the drainer replaying BBolt on
	// next start) then spawns the gRPC send in a goroutine. Before this
	// split, a slow backend would block the container-event goroutine
	// for up to sendTimeout per dying container, serialising every
	// subsequent start/die/sibling_start behind it.
	h.ViolationSink.ReportAsync(ctx, result.Info, &result.Stats, false, time.Time{})
}
