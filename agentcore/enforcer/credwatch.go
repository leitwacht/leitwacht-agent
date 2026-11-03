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
	// ReportOnly is true when the matched path is in the report-only
	// class (registry-login files such as /.docker/config.json). The BPF
	// program emitted the event and allowed the open regardless of mode;
	// userspace must never kill on it. Distinct from ObserveOnly, which
	// is a per-container mode: ReportOnly is a property of the path.
	// ObserveOnly is also set whenever ReportOnly is, so a consumer that
	// only checks ObserveOnly never kills on a report-only event;
	// check ReportOnly first to tell the two apart.
	ReportOnly bool
}

// CredwatchConfig holds credwatch enforcement configuration.
type CredwatchConfig struct {
	Enabled bool
	// WatchedPaths are suffixes denied (and the container killed) in
	// enforce mode, e.g. "/.ssh/id_rsa".
	WatchedPaths []string
	// ReportOnlyPaths are suffixes that are reported when opened but
	// never denied, even in enforce mode (registry logins such as
	// "/.docker/config.json"). A suffix listed here
	// and in WatchedPaths is report-only; when different suffixes match
	// one path, the longest wins.
	ReportOnlyPaths []string
	// ExcludedPaths are suffixes with no event and no enforcement at
	// all. Exclude beats both WatchedPaths and ReportOnlyPaths.
	ExcludedPaths []string
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
	CgroupID    uint64   // first registered id (kept for callers that want one)
	CgroupIDs   []uint64 // every registered id: scope and any /init leaf
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

	// credwatchKindReportOnly is OR-ed into the kind byte by the BPF
	// program for report-only matches (CW_KIND_REPORT_ONLY).
	credwatchKindReportOnly = 0x80
)

// BPF map value classes for the watched_* maps (CW_CLASS_* in credwatch.c).
const (
	credwatchClassWatched    = 1
	credwatchClassReportOnly = 2
)

// credwatchKindReportOnlyFlag reports whether the BPF kind byte carries
// the report-only marker.
func credwatchKindReportOnlyFlag(kind uint8) bool {
	return kind&credwatchKindReportOnly != 0
}

// credwatchReason maps a BPF event kind to its advisory reason string.
func credwatchReason(kind uint8) string {
	switch kind &^ credwatchKindReportOnly {
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

// allCgroupIDs returns every cgroup id registered for the container.
func (s *credwatchContainerState) allCgroupIDs() []uint64 {
	if len(s.CgroupIDs) > 0 {
		return s.CgroupIDs
	}

	return []uint64{s.CgroupID}
}
