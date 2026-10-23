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
	// Reason says which hook produced the event: "open",
	// "rename", "link" or "dpath_fail" (open of a watched name whose full
	// path could not be resolved).
	Reason string
	// ObserveOnly mirrors the per-container FLAG_OBSERVE_ONLY bit
	// the BPF program was configured with. When true, the BPF
	// program emitted this event but DID NOT deny the open — the
	// userspace callback should also skip its kill path.
	ObserveOnly bool
}

// CredwatchConfig holds credwatch enforcement configuration.
type CredwatchConfig struct {
	Enabled       bool
	WatchedPaths  []string // path suffixes to watch, e.g. "/.ssh/id_rsa"
	ExcludedPaths []string // suffixes to exclude from watching
}

// credwatchEventBPF matches the BPF struct credwatch_event (packed, 165 bytes).
type credwatchEventBPF struct {
	CgroupID    uint64
	PID         uint32
	Comm        [16]byte
	Path        [128]byte
	TimestampNs uint64
	Kind        uint8
}

// credwatchContainerState tracks cgroup ID for a container in the credwatch LSM.
type credwatchContainerState struct {
	CgroupID    uint64
	AddedAt     time.Time
	ObserveOnly bool
}

// Flag constants for cgroup_proc_config.flags (matching BPF defines).
const (
	credwatchFlagMonitored      = 1
	credwatchFlagAllowCredWatch = 4
	// credwatchFlagObserveOnly: emit the ringbuf event but DON'T
	// deny the cred-file open. For sandboxed detonation
	// environments — see credwatch.c's FLAG_OBSERVE_ONLY comment.
	credwatchFlagObserveOnly = 8
)

// credwatchEventSize is the expected packed size of struct credwatch_event in BPF bytecode.
const credwatchEventSize = 165

// credwatch_event.kind values (CW_KIND_* in credwatch.c).
const (
	credwatchKindOpen      = 0
	credwatchKindRename    = 1
	credwatchKindLink      = 2
	credwatchKindDPathFail = 3
)

// credwatchReason maps a BPF event kind to its advisory reason string.
func credwatchReason(kind uint8) string {
	switch kind {
	case credwatchKindRename:
		return "rename"
	case credwatchKindLink:
		return "link"
	case credwatchKindDPathFail:
		return "dpath_fail"
	default:
		return "open"
	}
}
