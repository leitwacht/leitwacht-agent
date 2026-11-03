//go:build linux

package enforcer

import "testing"

// TestLSMEventAttributionDescendantCgroup pins the userspace half of
// descendant-cgroup coverage: an event from a task in an unregistered
// child cgroup carries the matched container cgroup id, and is
// attributed to that container (not dropped as unattributed).
func TestLSMEventAttributionDescendantCgroup(t *testing.T) {
	const (
		containerCg = uint64(1001)
		childCg     = uint64(2002)
	)

	mgr := NewManager(testLogger(), 1, nil, nil, nil, CredwatchConfig{}, ProcMemConfig{})

	mgr.credwatchCgroupToContainer[containerCg] = "ctr-a"
	mgr.credwatchContainers["ctr-a"] = &credwatchContainerState{CgroupID: containerCg, ObserveOnly: true}
	mgr.procMemCgroupMap[containerCg] = "ctr-a"
	mgr.procMemContainers["ctr-a"] = &procMemContainerState{CgroupID: containerCg}

	var (
		cw []CredwatchEvent
		pm []ProcMemEvent
	)

	mgr.OnCredwatchEvent = func(e CredwatchEvent) { cw = append(cw, e) }
	mgr.OnProcMemEvent = func(e ProcMemEvent) { pm = append(pm, e) }

	mgr.handleCredwatchBPFEvent(credwatchEventBPF{CgroupID: childCg, ContainerCgroupID: containerCg, Kind: credwatchKindOpen})
	mgr.handleProcMemBPFEvent(procMemEventBPF{CgroupID: childCg, ContainerCgroupID: containerCg})

	// An event that carries only a registered leaf id (old exact-match
	// shape) is still attributed.
	mgr.handleCredwatchBPFEvent(credwatchEventBPF{CgroupID: containerCg, Kind: credwatchKindOpen})

	// An unknown cgroup stays unattributed.
	mgr.handleCredwatchBPFEvent(credwatchEventBPF{CgroupID: childCg, ContainerCgroupID: 9999, Kind: credwatchKindOpen})

	if len(cw) != 3 || len(pm) != 1 {
		t.Fatalf("got %d credwatch / %d proc_mem events, want 3 / 1", len(cw), len(pm))
	}

	if cw[0].ContainerID != "ctr-a" || cw[0].CgroupID != childCg || cw[0].ContainerCgroupID != containerCg || !cw[0].ObserveOnly {
		t.Errorf("credwatch descendant event wrong: %+v", cw[0])
	}

	if pm[0].ContainerID != "ctr-a" || pm[0].CgroupID != childCg || pm[0].ContainerCgroupID != containerCg {
		t.Errorf("proc_mem descendant event wrong: %+v", pm[0])
	}

	if cw[1].ContainerID != "ctr-a" {
		t.Errorf("leaf-only event not attributed: %+v", cw[1])
	}

	if cw[2].ContainerID != "" {
		t.Errorf("unknown cgroup must stay unattributed: %+v", cw[2])
	}
}
