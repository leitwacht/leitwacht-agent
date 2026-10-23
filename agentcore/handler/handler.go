// Package handler processes container lifecycle events from the watcher,
// freezes each container until enforcement is attached (see Freezer),
// fetches its policy, runs security checks, attaches enforcement, and
// reports back. Edition-neutral: EE wires it with gRPC
// sinks, CE wires it with stdout/Prometheus/webhook sinks. The handler
// itself never imports either edition's wire format.
package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/internal/idutil"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/violation"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/watcher"
)

const (
	// handleStartTimeout bounds one HandleStart (policy lookup + attach).
	// The freeze hold is bounded separately and independently of it (see
	// Freezer): a container is never left frozen past
	// max(FreezeTimeout, handleStartTimeout) + freezeHoldSlack, so a stuck
	// handler cannot cause kubelet liveness failures or pod deadline expiry.
	handleStartTimeout = 10 * time.Second
)

// truncID is the package-local alias for idutil.Trunc.
var truncID = idutil.Trunc

// infoFromEvent projects the identity-bearing fields of a watcher event
// onto the enforcer's ContainerInfo. The two structs intentionally stay
// separate (one is the watcher's input shape, the other the enforcer's
// retained-for-reporting shape) — the projection lives here so adding a
// new identity field is a one-line edit instead of a multi-site sweep.
//
// pol must already be job-scoped (post ForJob): CredwatchMode/ProcMemMode
// are read verbatim as the resolved per-job LSM enforcement mode.
func infoFromEvent(ev watcher.ContainerEvent, pol *policy.ResolvedPolicy) enforcer.ContainerInfo {
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
		CredwatchMode:    pol.CredwatchMode,
		ProcMemMode:      pol.ProcMemMode,
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

	// FreezeTimeout bounds how long HandleStart waits for the container's
	// cgroup to report frozen. The freeze applies ONLY to the Docker API
	// runtime (Docker, and Podman through its Docker-compatible socket);
	// containerd/CRI (Kubernetes) events are never frozen, since K8s relies
	// on the leitwacht-initc pre-job gate. BEHAVIOUR CHANGE: the zero value means
	// DefaultFreezeTimeout (5s) with the freeze ENABLED, so a Handler
	// constructed without this field now freezes every container it
	// attaches. To turn the freeze off set DisableFreeze (or a negative
	// FreezeTimeout); not recommended, the job then runs with unfiltered
	// egress until attach completes.
	FreezeTimeout time.Duration

	// DisableFreeze turns the pre-attach freeze off explicitly. Equivalent
	// to a negative FreezeTimeout.
	DisableFreeze bool

	// FreezeStateDir is where freeze markers are persisted so RecoverFrozen
	// can release containers a crashed agent left frozen. Empty means
	// DefaultFreezeStateDir. Ignored when Freezer is set.
	FreezeStateDir string

	// Freezer overrides the container freezer. Nil builds one lazily that
	// uses the cgroup v2 freezer, falling back to the Watcher's pause API
	// when the Watcher implements ContainerPauser.
	Freezer *Freezer

	freezerOnce      sync.Once
	freezeWarnedOnce sync.Once
	freezerResolved  *Freezer
	killWireOnce     sync.Once
}

// freezer returns the configured or lazily built Freezer.
func (h *Handler) freezer() *Freezer {
	h.freezerOnce.Do(func() {
		if h.Freezer != nil {
			h.freezerResolved = h.Freezer

			return
		}

		f := &Freezer{Logger: h.Logger, StateDir: h.FreezeStateDir}
		if p, ok := h.Watcher.(ContainerPauser); ok {
			f.Pauser = p
		}

		h.freezerResolved = f
	})

	// The hard-limit callback is wired whether the Freezer is ours or
	// supplied: a block-mode freeze that expires kills, it does not release.
	h.killWireOnce.Do(func() {
		if h.freezerResolved.Kill == nil {
			h.freezerResolved.Kill = func(id, scope string) { h.killContainer(id, scope) }
		}
	})

	return h.freezerResolved
}

// Shutdown releases every container still frozen. Call it before the
// agent exits so no workload is left stopped.
func (h *Handler) Shutdown() {
	h.freezer().ThawAll()
}

// RecoverFrozen releases containers a previous agent process left frozen
// (crash, SIGKILL, OOM). Call it once at startup, BEFORE enumerating
// running containers: a frozen or paused workload never reports as
// running and would otherwise stay stopped forever.
func (h *Handler) RecoverFrozen(ctx context.Context) int {
	return h.freezer().RecoverFrozen(ctx)
}

const killTimeout = 5 * time.Second

// killContainer kills a container on a fresh context (the handler's own
// may be spent) and checks the result. If the runtime kill fails it falls
// back to the cgroup v2 kill switch on the container scope. Returns nil
// when the container was killed.
func (h *Handler) killContainer(containerID, scope string) error {
	kctx, cancel := context.WithTimeout(context.Background(), killTimeout)
	defer cancel()

	err := h.Watcher.KillContainer(kctx, containerID)
	if err == nil {
		return nil
	}

	// Already exited / no longer known to the runtime: the goal (it is not
	// running) is met.
	if errors.Is(err, os.ErrNotExist) || cerrdefs.IsNotFound(err) {
		return nil
	}

	h.Logger.Error("runtime kill failed", "container_id", truncID(containerID), "error", err)

	if scope != "" {
		if werr := writeCgroupFile(filepath.Join(scope, "cgroup.kill"), "1"); werr == nil {
			return nil
		} else {
			h.Logger.Error("cgroup.kill fallback failed", "container_id", truncID(containerID), "error", werr)
		}
	}

	return err
}

// kill returns the advisory action to report: "killed", or "kill_failed"
// when neither the runtime nor cgroup.kill could stop the container.
func (h *Handler) kill(ev watcher.ContainerEvent, scope string) string {
	if err := h.killContainer(ev.ContainerID, scope); err != nil {
		return "kill_failed"
	}

	return "killed"
}

// containerScope returns the container's cgroup scope directory: the
// kernel's view from /proc first, then the runtime-supplied path if it is
// under the cgroup mount. Empty when neither is usable.
func (h *Handler) containerScope(ev watcher.ContainerEvent) string {
	if h.Enforcer != nil && ev.PID > 0 {
		if p, err := h.Enforcer.CgroupPathForPID(ev.PID); err == nil && p != "" {
			return enforcer.ScopeCgroup(p)
		}
	}

	// containerd may report a systemd-style "slice:prefix:name" here, and
	// anything outside the cgroup mount is not a path we may write to.
	if strings.HasPrefix(ev.CgroupPath, cgroupMount+"/") {
		return enforcer.ScopeCgroup(ev.CgroupPath)
	}

	return ""
}

const cgroupMount = "/sys/fs/cgroup"

// freezeRuntime reports whether the Watcher's runtime is one the pre-attach
// freeze applies to: the Docker API (including Podman's compatible API).
func (h *Handler) freezeRuntime() bool {
	rn, ok := h.Watcher.(watcher.RuntimeNamer)

	return ok && rn.Runtime() == watcher.RuntimeDocker
}

// freezeBeforeAttach stops the container until enforcement is attached.
// It returns a nil *Freeze (whose Thaw is a no-op) when no freeze is
// needed or possible, and an error only when a freeze was attempted and
// failed in a way the caller must act on. ErrFreezeUnavailable and
// os.ErrNotExist (container already gone) are returned for the caller to
// treat as "proceed unfrozen".
func (h *Handler) freezeBeforeAttach(ctx context.Context, ev watcher.ContainerEvent) (*Freeze, error) {
	if h.DisableFreeze || h.FreezeTimeout < 0 || ev.HasGVisor {
		return nil, nil //nolint:nilnil // nil Freeze is a valid no-op handle
	}

	// Freeze applies to the Docker API runtime only (Docker, and Podman via
	// its Docker-compatible socket). It is never applied to containerd/CRI
	// (Kubernetes) events, whatever the pod-attach state: K8s pods are
	// gated by the leitwacht-initc init container, which holds entrypoints
	// until the DNS proxy reports the netns enforcing. A watcher that does
	// not identify its runtime is treated as non-freezable.
	if !h.freezeRuntime() {
		return nil, nil //nolint:nilnil // nil Freeze is a valid no-op handle
	}

	scope := h.containerScope(ev)

	z, err := h.freezer().Freeze(ctx, ev.ContainerID, scope, h.FreezeTimeout)
	if err != nil && errors.Is(err, os.ErrNotExist) && ev.PID > 0 && procExists(ev.PID) {
		// The process is alive but we could not find its cgroup directory
		// (path mismatch, namespaced mount). That is "cannot freeze by
		// cgroup", not "container gone": use the runtime pause API.
		z, err = h.freezer().FreezePause(ctx, ev.ContainerID)
	}

	if err != nil {
		return nil, err
	}

	// Until the policy is known assume the configured default; HandleStart
	// refines this once it has resolved the job's action.
	z.SetKillOnExpire(h.DefaultAction == policy.ActionBlock)

	return z, nil
}

func procExists(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))

	return err == nil
}

// HandleStart processes a container start event: freezes the container so it
// cannot egress before enforcement is ready, fetches policy, runs security
// checks, attaches enforcement, then thaws it.
//
// Failure handling is fail-closed in block mode: if the freeze cannot be
// confirmed or attach fails (other than the container having already
// exited), the container is killed and an advisory with action "killed" is
// sent. In audit mode the container is thawed and a "warned" advisory is
// sent. The container is always thawed on return.
//
//nolint:funlen // orchestration handler with sequential security steps
func (h *Handler) HandleStart(ctx context.Context, ev watcher.ContainerEvent) {
	// Bound policy lookup + attach. The freeze itself has its own hard
	// limit (Freezer) so a wedged handler can never leave a container
	// frozen.
	ctx, cancel := context.WithTimeout(ctx, handleStartTimeout)
	defer cancel()

	h.Logger.Info("handling container start",
		"container_id", truncID(ev.ContainerID),
		"project", ev.ProjectPath,
		"job_id", ev.JobID,
	)

	// Close the pre-attach window first. Docker and Podman only (see
	// freezeBeforeAttach; never containerd/K8s): there is no pod sandbox, so without a freeze the job runs
	// with unfiltered egress and no DNS redirect until policy lookup, eBPF
	// load, nftables setup and cgroup attach finish. The deferred Thaw is
	// the safety net for every early return below.
	freeze, freezeErr := h.freezeBeforeAttach(ctx, ev)
	defer freeze.Thaw()

	scope := h.containerScope(ev)

	// On K8s the build container's eBPF cgroup attach race is closed by
	// the pod-sandbox attach path (HandlePodSandboxStart →
	// Manager.AttachPodSandbox): when the pause container's /tasks/start
	// fires — strictly before any user container in the pod runs — the
	// agent derives the parent pod cgroup and attaches the cgroup_skb
	// program once at that level. Every container that subsequently joins
	// the pod (init, helper, build) is filtered automatically; the build
	// container's first packet hits an already-attached program, which
	// runs the audit-all placeholder until this container's own Attach
	// reconciles the netns to its policy: a known window of tens of ms in
	// which egress is allowed and logged. leitwacht-initc releases on the
	// pod-level attach, not on that reconcile. The
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

	freeze.SetKillOnExpire(pol.Action == policy.ActionBlock)

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
	// advisories, no container kills. Skip straight to attach. Nothing is
	// enforced for them, so release the freeze first.
	if passiveOnly {
		freeze.Thaw()
		h.attachSentinelOnly(ctx, ev, pol)

		return
	}

	// DinD — block mode kills, audit mode warns.
	if ev.HasDinD {
		if pol.Action == policy.ActionBlock {
			h.Logger.Error("DinD detected in block mode, killing container", "container_id", truncID(ev.ContainerID))
			act := h.kill(ev, scope)

			report(advisory.KindDinDDetected,
				"Docker-in-Docker detected — container killed (block mode).\n\n"+
					"Fix: Replace DinD with kaniko, buildah, or Docker socket binding for image builds. "+
					"DinD spawns nested containers whose network traffic cannot be enforced.",
				act)

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
			act := h.kill(ev, scope)

			report(advisory.KindSocketMount,
				"Docker socket bind mount detected — container killed (block mode).\n\n"+
					"Fix: Remove the /var/run/docker.sock volume mount from the runner's volume configuration "+
					"(config.toml [runners.docker] volumes, or Helm values runners.config volumes). "+
					"Socket access allows spawning sibling containers that bypass network enforcement.",
				act)

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
			act := h.kill(ev, scope)

			report(advisory.KindFFNetworkPerBuildMissing,
				"FF_NETWORK_PER_BUILD not enabled — container killed (block mode).\n\n"+
					"Fix: Set FF_NETWORK_PER_BUILD = \"true\" in the runner's environment variables "+
					"(config.toml [[runners.environment]], Helm values runners.config environment, or as a CI/CD variable in GitLab). "+
					"This isolates each job's network stack.",
				act)

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

	// A freeze that was attempted and failed (timeout, write error) leaves
	// the container in an unknown state with no confirmed window closure.
	// "Unavailable" and "already gone" are not failures: there is nothing
	// to hold, and attach below reports a vanished container itself.
	if freezeErr != nil && !h.handleFreezeFailure(ctx, ev, pol, freezeErr, scope, report) {
		return
	}

	_, attachErr := h.Enforcer.Attach(ctx, infoFromEvent(ev, pol), ev.PID, pol)
	if attachErr == nil {
		freeze.Thaw()

		return
	}

	// Short-lived helper containers (e.g. GitLab Runner init containers) may exit
	// before we can attach. Don't fire an advisory for these — the build container
	// will start momentarily and attach successfully.
	if errors.Is(attachErr, os.ErrNotExist) {
		h.Logger.Debug("container exited before attach, skipping advisory", "container_id", truncID(ev.ContainerID))

		return
	}

	// A duplicate start event while the first attach is in flight: the
	// first call owns the outcome (and the freeze).
	if errors.Is(attachErr, enforcer.ErrAttachInProgress) {
		h.Logger.Debug("attach already in progress, ignoring duplicate start", "container_id", truncID(ev.ContainerID))

		return
	}

	h.Logger.Error("attach enforcement failed", "container_id", truncID(ev.ContainerID), "error", attachErr)

	fix := "Fix: Ensure the host kernel supports eBPF (a maintained kernel current on its distro's security stream), the agent has CAP_SYS_ADMIN/CAP_BPF, " +
		"and the container PID namespace is accessible. Check agent logs for details."

	if errors.Is(attachErr, enforcer.ErrMaxConcurrent) {
		fix = "Fix: Raise the agent's maximum concurrent enforcement setting or reduce parallel jobs per node."
	}

	// Fail closed in block mode: a container that could not be put under
	// enforcement must not run as if it were.
	if pol.Action == policy.ActionBlock {
		h.Logger.Error("enforcement not attached in block mode, killing container", "container_id", truncID(ev.ContainerID))
		act := h.kill(ev, scope)

		report(advisory.KindAttachFailure,
			fmt.Sprintf("eBPF enforcement failed to attach — container killed (block mode): %s\n\n%s", attachErr, fix),
			act)

		return
	}

	report(advisory.KindAttachFailure,
		fmt.Sprintf("eBPF enforcement failed to attach: %s\n\n%s", attachErr, fix),
		"warned")
}

// handleFreezeFailure acts on a freeze error. It returns true when
// HandleStart should continue to attach, false when the container was
// dealt with (killed in block mode).
func (h *Handler) handleFreezeFailure(
	ctx context.Context, ev watcher.ContainerEvent, pol *policy.ResolvedPolicy,
	freezeErr error, scope string, report func(advisory.Kind, string, string),
) bool {
	switch {
	case errors.Is(freezeErr, os.ErrNotExist):
		return true
	case errors.Is(freezeErr, ErrFreezeUnavailable):
		h.freezeWarnedOnce.Do(func() {
			h.Logger.Warn("pre-attach freeze unavailable on this host; containers run unfiltered until attach completes",
				"error", freezeErr)
		})

		return true
	}

	h.Logger.Error("pre-attach freeze failed", "container_id", truncID(ev.ContainerID), "error", freezeErr)

	if pol.Action == policy.ActionBlock {
		act := h.kill(ev, scope)

		report(advisory.KindAttachFailure,
			fmt.Sprintf("could not hold the container until enforcement attached — container killed (block mode): %s", freezeErr),
			act)

		return false
	}

	report(advisory.KindAttachFailure,
		fmt.Sprintf("could not hold the container until enforcement attached; it may have run unfiltered briefly: %s", freezeErr),
		"warned")

	return true
}

// attachSentinelOnly attaches DNS interception with a no-rule audit-pass
// policy so the leitwacht-init init container in a non-enrolled project's
// CI pod exits. No security checks run and no advisories are emitted —
// an opted-out project should not generate pressure on operators.
func (h *Handler) attachSentinelOnly(ctx context.Context, ev watcher.ContainerEvent, pol *policy.ResolvedPolicy) {
	_, err := h.Enforcer.Attach(ctx, infoFromEvent(ev, pol), ev.PID, pol)
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
// No freeze, no policy fetch — runs in audit-all mode until the build container
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
