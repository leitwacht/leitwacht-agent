package enforcer

import (
	"fmt"
	"os"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/policy"
)

// PodSandboxInfo describes the K8s pause container that anchors a pod's
// netns + cgroup hierarchy.
type PodSandboxInfo struct {
	PodUID     string // io.kubernetes.pod.uid
	SandboxID  string // sandbox container ID
	PID        int    // sandbox process PID (for netns inode lookup)
	CgroupPath string // sandbox container's absolute cgroup path
}

// AttachPodSandbox sets up pod-level eBPF cgroup_skb attach on the K8s
// pause container's task-start. Derives the parent pod cgroup from the
// sandbox's cgroup, attaches the eBPF egress filter there once for the
// whole pod, and primes netns-level DNS infrastructure with an audit-all
// policy. When real containers (init / helper / build) later call Attach,
// they take the joiner branch, swap the policy in place, and skip the
// per-container AttachCgroup call.
//
// Returns nil with a warn-log for the per-container fallback when the
// cgroup path doesn't match a recognised K8s shape (Docker, Podman, plain
// containerd) or when the derived pod cgroup directory isn't on disk
// (pod being torn down concurrently).
func (m *Manager) AttachPodSandbox(info PodSandboxInfo) error {
	start := time.Now()

	podCgroup, err := PodCgroupFromContainer(info.CgroupPath)
	if err != nil {
		m.logger.Warn("pod-cgroup derivation failed at sandbox start; per-container fallback will engage on real-container attach",
			"err", err,
			"sandbox_cgroup", info.CgroupPath,
			"pod_uid", info.PodUID,
		)

		return nil
	}

	// Belt-and-braces: explicit stat for diagnostic clarity. AttachCgroup
	// would surface ENOENT itself, but the explicit warn here makes the
	// concurrent-teardown case obvious in logs.
	_, statErr := os.Stat(podCgroup)
	if statErr != nil {
		m.logger.Warn("pod cgroup directory missing at sandbox start; per-container fallback will engage",
			"pod_cgroup", podCgroup,
			"err", statErr,
			"pod_uid", info.PodUID,
		)

		return nil
	}

	netnsIno, netnsErr := m.platform.NetnsInode(info.PID)
	if netnsErr != nil {
		return fmt.Errorf("sandbox netns inode lookup: %w", netnsErr)
	}

	if netnsIno == 0 {
		return fmt.Errorf("sandbox pid %d: %w", info.PID, ErrNetnsInodeZero)
	}

	// SandboxChanged + duplicate-ignore are caller-specific early returns:
	// they need the existing-nctx state read under m.mu before deciding,
	// which doesn't fit acquireOrCreateNetnsContext's "lookup-or-create"
	// shape. Handle them inline, then fall through to the helper.
	if handled, sandboxErr := m.handleExistingPodSandbox(netnsIno, podCgroup, info); handled {
		return sandboxErr
	}

	auditPol := &policy.ResolvedPolicy{
		Action:   policy.ActionAudit,
		Enrolled: true,
		RuleSets: map[string][]policy.Rule{"": nil},
	}

	nctx, _, err := m.acquireOrCreateNetnsContext(netnsIno, func(n *NetnsContext) error {
		return m.initNetnsContext(n, info.PID, auditPol)
	})
	if err != nil {
		return fmt.Errorf("init netns for pod sandbox: %w", err)
	}

	attachErr := m.attachPodLink(nctx, podCgroup, info)
	if attachErr != nil {
		// Only a fresh-creator context should be torn down on attach
		// failure; a promoted-existing nctx still has real containers
		// or other refcounts keeping it alive. acquireOrCreateNetnsContext
		// returns the same nctx for both, so consult refcount instead
		// of the created flag.
		m.mu.Lock()
		shouldTeardown := nctx.refcount == 0

		if shouldTeardown {
			delete(m.netnsContexts, netnsIno)
		}
		m.mu.Unlock()

		if shouldTeardown {
			m.teardownNetnsContext(nctx)
		}

		return attachErr
	}

	m.logger.Info("pod sandbox attached at pod cgroup",
		"pod_uid", info.PodUID,
		"sandbox_id", truncID(info.SandboxID),
		"pod_cgroup", podCgroup,
		"netns_inode", netnsIno,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

// handleExistingPodSandbox inspects the existing NetnsContext (if any)
// for netnsIno and returns (true, …) if the call was fully handled here:
//
//   - duplicate sandbox-start: ignored, returns (true, nil)
//   - SandboxChanged: tears down the old pod-cgroup state and re-attaches,
//     returns (true, attachErr)
//
// Returns (false, nil) when the caller should fall through to the
// create-or-promote path via acquireOrCreateNetnsContext.
func (m *Manager) handleExistingPodSandbox(netnsIno uint64, podCgroup string, info PodSandboxInfo) (bool, error) {
	m.mu.Lock()

	nctx := m.netnsContexts[netnsIno]
	if nctx == nil {
		m.mu.Unlock()

		return false, nil
	}

	if !nctx.podAttached {
		// Real container raced ahead of the sandbox event; fall through
		// so the helper waits on its <-ready and we then promote it.
		m.mu.Unlock()

		return false, nil
	}

	if nctx.sandboxID == info.SandboxID {
		m.mu.Unlock()
		m.logger.Debug("duplicate pod_sandbox_start ignored", "sandbox_id", truncID(info.SandboxID))

		return true, nil
	}

	// SandboxChanged: kubelet replaced the sandbox for this pod
	// (network-config errors, OOM, systemd vs runtime fights). The new
	// sandbox often shares the netns inode in practice; close the old
	// pod link and re-attach at the re-derived pod cgroup. Recorder
	// map state is preserved.
	m.logger.Info("sandbox replaced for pod; re-attaching pod-level eBPF",
		"pod_uid", info.PodUID,
		"old_sandbox", nctx.sandboxID,
		"new_sandbox", info.SandboxID,
	)

	oldLink := nctx.podCgroupLink
	oldCgID := nctx.podCgroupID
	m.mu.Unlock()

	// Attach the new link BEFORE closing the old one (requires cgroup
	// bpf_link multi-attach, Linux >= 5.7; the agent already needs links): closing first leaves
	// a window with no egress filter on the pod cgroup while containers
	// are running. Links are independently attachable to one cgroup, so the
	// program briefly runs twice, which is harmless. On failure the old
	// link and state stay in place, so the pod keeps its filter.
	attachErr := m.attachPodLink(nctx, podCgroup, info)
	if attachErr != nil {
		return true, attachErr
	}

	// attachPodLink took a reference for the new sandbox. Release the
	// replaced sandbox's here; without this release each SandboxChanged
	// leaked one, so the netns context could never reach refcount 0 and
	// was never torn down. The count never dips mid-replacement.
	m.mu.Lock()
	nctx.refcount--
	newCgID := nctx.podCgroupID
	m.mu.Unlock()

	if oldLink != nil {
		_ = oldLink.Close() // swallow ENOENT
	}

	if oldCgID != newCgID {
		nctx.mu.Lock()
		delete(nctx.cgroupRecorders, oldCgID)
		nctx.mu.Unlock()
	}

	return true, nil
}

// attachPodLink performs the AttachCgroup call and stores pod-attach state
// on nctx under m.mu. Refcount is incremented with it, for symmetry with
// Detach.
func (m *Manager) attachPodLink(nctx *NetnsContext, podCgroup string, info PodSandboxInfo) error {
	start := time.Now()

	link, err := nctx.ebpf.AttachCgroup(podCgroup)
	if err != nil {
		return fmt.Errorf("attach pod cgroup %s: %w", podCgroup, err)
	}

	cgID, idErr := m.platform.CgroupID(podCgroup)
	if idErr != nil {
		_ = link.Close()

		return fmt.Errorf("get pod cgroup id: %w", idErr)
	}

	// Route softirq-context fallbacks (when bpf_get_current_cgroup_id()
	// returns the pod cgroup id rather than a leaf container's id) to the
	// pod-shared DNS recorder, instead of letting them fall back to the
	// arbitrary first-registered recorder in lookupPacketRecorder.
	if nctx.sharedDNSRecorder != nil {
		nctx.mu.Lock()
		nctx.cgroupRecorders[cgID] = nctx.sharedDNSRecorder
		nctx.mu.Unlock()
	}

	// Pod-attach state is read under m.mu (attachEnforcer, sandbox
	// bookkeeping) and by other goroutines handling sibling events, so
	// it is written under m.mu as well. Refcount moves with it.
	m.mu.Lock()
	nctx.podCgroupLink = link
	nctx.podCgroupID = cgID
	nctx.podUID = info.PodUID
	nctx.sandboxID = info.SandboxID
	nctx.podAttached = true
	nctx.refcount++
	m.mu.Unlock()

	// Egress is live at the pod cgroup before any user container runs, so
	// arm the DNS attach-liveness signal here: leitwacht-initc (an init
	// container that carries no job env, so it never reaches Attach itself)
	// must be released as soon as the pod-level program is linked, or every
	// job pod would wait out its deadline. Known window: until the build
	// container's own Attach reconciles the netns to its policy, egress
	// runs under this audit-all placeholder (allowed and logged).
	nctx.egressAttached.Store(true)

	m.logger.Debug("pod cgroup link bound",
		"pod_uid", info.PodUID,
		"sandbox_id", truncID(info.SandboxID),
		"pod_cgroup", podCgroup,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

// DetachPodSandbox releases the pod-level eBPF attach. Decrements refcount;
// triggers (deferred) teardown if the pod has no remaining real containers.
// No-op if no nctx matches the sandboxID — recovery may emit pod_sandbox_die
// for sandboxes that never produced a successful AttachPodSandbox.
func (m *Manager) DetachPodSandbox(podUID, sandboxID string) {
	start := time.Now()

	m.mu.Lock()

	var target *NetnsContext

	for _, nctx := range m.netnsContexts {
		if nctx.sandboxID == sandboxID {
			target = nctx

			break
		}
	}

	if target == nil {
		m.mu.Unlock()

		return
	}

	target.refcount--
	remaining := target.refcount
	teardown := remaining == 0

	lastContainer := teardown
	if teardown && target.inode != 0 && m.NetnsGrace > 0 {
		go m.deferredTeardown(target)

		teardown = false
	} else if teardown && target.inode != 0 {
		delete(m.netnsContexts, target.inode)
	}

	m.mu.Unlock()

	// If this is the last container in the netns, stop the DNS flush goroutine
	// so the final snapshot captures all data. Symmetric with Detach.
	if lastContainer && target.dnsFlushCancel != nil && target.dnsFlushStarted.Load() {
		target.dnsFlushCancel()
		<-target.dnsFlushDone
		target.dnsFlushStarted.Store(false)
	}

	if teardown {
		m.teardownNetnsContext(target)
	}

	m.logger.Info("pod sandbox detached",
		"pod_uid", podUID,
		"sandbox_id", truncID(sandboxID),
		"refcount", remaining,
		"teardown", teardown,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
