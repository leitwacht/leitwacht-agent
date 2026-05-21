package enforcer

import "time"

// CredwatchEvent is the Go-side representation of a BPF credential file access detection event.
type CredwatchEvent struct {
	ContainerID string
	CgroupID    uint64
	PID         uint32
	Comm        string
	Path        string
	TimestampNs int64
}

// CredwatchConfig holds credwatch enforcement configuration.
type CredwatchConfig struct {
	Enabled       bool
	WatchedPaths  []string // path suffixes to watch, e.g. "/.ssh/id_rsa"
	ExcludedPaths []string // suffixes to exclude from watching
}

// credwatchEventBPF matches the BPF struct credwatch_event (packed, 164 bytes).
type credwatchEventBPF struct {
	CgroupID    uint64
	PID         uint32
	Comm        [16]byte
	Path        [128]byte
	TimestampNs uint64
}

// credwatchContainerState tracks cgroup ID for a container in the credwatch LSM.
type credwatchContainerState struct {
	CgroupID uint64
	AddedAt  time.Time
}

// Flag constants for cgroup_proc_config.flags (matching BPF defines).
const (
	credwatchFlagMonitored      = 1
	credwatchFlagAllowCredWatch = 4
)

// credwatchEventSize is the expected packed size of struct credwatch_event in BPF bytecode.
const credwatchEventSize = 164
