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
	CgroupID uint64
	AddedAt  time.Time
}

// Flag constants for cgroup_proc_config.flags (matching BPF defines).
const (
	procMemFlagMonitored     = 1
	procMemFlagAllowProcRead = 2
)

// procMemEventSize is the expected packed size of struct proc_mem_event in BPF bytecode.
const procMemEventSize = 100
