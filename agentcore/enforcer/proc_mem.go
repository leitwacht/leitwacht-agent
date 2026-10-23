package enforcer

import "time"

// ProcMemEvent is the Go-side representation of a BPF /proc/*/mem read detection event.
type ProcMemEvent struct {
	ContainerID string
	CgroupID    uint64
	PID         uint32
	Comm        string
	Path        string
	TimestampNs int64
	// ObserveOnly mirrors the per-container FLAG_OBSERVE_ONLY bit the
	// BPF program was configured with. When true, the BPF program
	// emitted this event but DID NOT deny the open — the userspace
	// callback should also skip its kill path.
	ObserveOnly bool
}

// ProcMemConfig holds proc_mem enforcement configuration.
type ProcMemConfig struct {
	Enabled bool
}

// procMemEventBPF matches the BPF struct proc_mem_event (packed, 100 bytes).
type procMemEventBPF struct {
	CgroupID    uint64
	PID         uint32
	Comm        [16]byte
	Path        [64]byte
	TimestampNs uint64
}

// procMemContainerState tracks cgroup ID for a container in the proc_mem LSM.
type procMemContainerState struct {
	CgroupID    uint64   // first registered id (kept for callers that want one)
	CgroupIDs   []uint64 // every registered id: scope and any /init leaf
	AddedAt     time.Time
	ObserveOnly bool
}

// Flag constants for cgroup_proc_config.flags (matching BPF defines).
const (
	procMemFlagMonitored     = 1
	procMemFlagAllowProcRead = 2
	// procMemFlagObserveOnly: emit the ringbuf event but DON'T deny
	// the /proc/<pid>/mem open. For sandboxed detonation — see
	// proc_mem.c's FLAG_OBSERVE_ONLY comment.
	procMemFlagObserveOnly = 4
)

// procMemEventSize is the expected packed size of struct proc_mem_event in BPF bytecode.
const procMemEventSize = 100

// allCgroupIDs returns every cgroup id registered for the container.
func (s *procMemContainerState) allCgroupIDs() []uint64 {
	if len(s.CgroupIDs) > 0 {
		return s.CgroupIDs
	}

	return []uint64{s.CgroupID}
}
