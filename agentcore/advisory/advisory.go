// Package advisory carries the plain-Go security advisory type and the
// sink interface the agent core uses to ship advisories. Adapters
// (gRPC reporter on EE; stdout/prom on CE) translate Advisory values
// to whatever wire format their upstream expects — agentcore never
// touches protobuf for this path.
package advisory

import "time"

// Kind identifies the specific class of security concern an advisory
// represents. Values mirror the wire-format `advisory_type` strings
// the backend consumes today; new kinds must be added here and to the
// gRPC adapter in lockstep so the schema stays single-sourced.
type Kind string

// Advisory kinds the agent emits today. Keep in sync with the comment
// on agentpb.SecurityAdvisory.AdvisoryType — the EE adapter writes
// these strings verbatim onto the wire.
const (
	KindDinDDetected             Kind = "dind_detected"
	KindSocketMount              Kind = "socket_mount"
	KindRootfulPodman            Kind = "rootful_podman"
	KindGVisorUnsupported        Kind = "gvisor_unsupported"
	KindFFNetworkPerBuildMissing Kind = "ff_network_per_build_missing"
	KindAttachFailure            Kind = "attach_failure"
	KindAgentStartupFailure      Kind = "agent_startup_failure"
	KindBPFLSMUnavailable        Kind = "bpf_lsm_unavailable"
	KindCredFileOpen             Kind = "cred_file_open"
	KindCredwatchLSMUnavailable  Kind = "credwatch_lsm_unavailable"
	KindProcMemRead              Kind = "proc_mem_read"
	KindProcMemLSMUnavailable    Kind = "proc_mem_lsm_unavailable"
	KindDNSViolationKill         Kind = "dns_violation_kill"
	// KindDNSConfig flags a container resolver configuration (ndots,
	// search domains) that amplifies lookups or carries non-cluster
	// suffixes. Informational; no enforcement change. EE carries it on
	// the existing advisory_type + message fields (no proto change); the
	// server must accept the new advisory_type string.
	KindDNSConfig Kind = "dns_config"
)

// Advisory is the plain-Go view of a single security concern the agent
// surfaces to its upstream. Field set mirrors agentpb.SecurityAdvisory
// so the gRPC adapter is a 1:1 copy; CE adapters render the same
// payload to NDJSON, prom labels, or webhook bodies without losing
// information.
//
// Hostname is left zero by callers — the sink fills it from per-process
// configuration so every emitter doesn't have to thread it through.
// OccurredAt likewise defaults to time.Now() inside the sink when zero.
type Advisory struct {
	Hostname     string
	ContainerID  string
	ProjectPath  string
	JobID        string
	JobURL       string
	Kind         Kind
	Message      string
	ActionTaken  string
	PolicyAction string
	OccurredAt   time.Time

	// Details is optional structured payload for sinks that can render it
	// (CE NDJSON/webhook). It is NOT carried by the EE gRPC adapter: every
	// advisory that sets Details must also put the same facts in Message.
	// Values may include container-controlled strings; render escaped.
	Details map[string]any
}
