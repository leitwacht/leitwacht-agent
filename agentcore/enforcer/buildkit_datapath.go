package enforcer

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"time"
)

// Kernel-side constants of the egress_bk object; must match
// egress_bk.h.
const (
	bkStatePending      uint8 = 0
	bkStateBound        uint8 = 1
	bkStateAmbiguous    uint8 = 2
	bkStateUnattributed uint8 = 3
	bkStateDegraded     uint8 = 4
	// bkStateDegradedLevel: the packet's cgroup is under none of the
	// configured BuildKit parents (cgroup layout mismatch).
	bkStateDegradedLevel uint8 = 5

	bkModeAudit  uint8 = 0
	bkModeShadow uint8 = 1
	bkModeBlock  uint8 = 2

	bkVerdictDropped    uint8 = 1
	bkVerdictObserved   uint8 = 2
	bkVerdictWouldBlock uint8 = 3
	bkVerdictAllowed    uint8 = 4

	// bkMaxSlots is the outer-array size of the slot tables.
	bkMaxSlots = 256

	// minBKDropEventSize is minDropEventSize plus verdict(1) + state(1) +
	// slot(4) + gen(4).
	minBKDropEventSize = minDropEventSize + 10
)

// Enforcement-state strings stamped on violations (Violation.EnforcementState).
const (
	EnfStateEnforced      = "enforced"
	EnfStateShadow        = "shadow"
	EnfStateAuditProject  = "audit_project"
	EnfStatePendingBind   = "pending_bind"
	EnfStateAmbiguous     = "ambiguous_multi_project"
	EnfStateUnattributed  = "unattributed"
	EnfStateDegradedCap   = "degraded_capacity"
	EnfStateDegradedHist  = "degraded_history"
	EnfStatePolicyUnavl   = "policy_unavailable"
	EnfStateDegradedLevel = "degraded_level"
)

// Extra drop reasons of the egress_bk object (DROP_REASON_* in egress_bk.h).
const (
	dropReasonDNSBypass uint8 = 3
	dropReasonIPv6      uint8 = 4
)

// BKCgroupPolicy is one bk_cgroup_policy entry.
type BKCgroupPolicy struct {
	Slot  uint32
	State uint8
	Mode  uint8
	Gen   uint32
}

// BKConfig is the bk_cfg content.
type BKConfig struct {
	// ParentIDs are the cgroup ids of the BuildKit parent cgroups (at most
	// bkMaxParents).
	ParentIDs []uint64
	// DNSUpstreams are the IPv4 addresses port 53 is allowed to in
	// SHADOW/BLOCK (at most bkMaxDNS); empty disables the pin.
	DNSUpstreams []net.IP
	// RunLevel, when nonzero, fixes the RUN cgroup level instead of
	// scanning for the parents. Tests only.
	RunLevel uint32
}

const (
	bkMaxParents = 8
	bkMaxDNS     = 4
)

// BKSlotRules is the rendered content of one slot: static IP rules
// split by action (the DNS-derived inner map starts empty).
type BKSlotRules struct {
	Deny  []BuildIPRule
	Allow []BuildIPRule
}

// BuildKitDatapath is the userspace face of the egress_bk object.
type BuildKitDatapath interface {
	// AttachCgroup attaches the program at a BuildKit cgroup parent.
	AttachCgroup(cgroupPath string) (CgroupLink, error)
	// SetConfig writes bk_cfg: the BuildKit parent cgroup ids (the
	// program finds the RUN level in-kernel from them), the DNS upstreams
	// of the port-53 pin, and an optional fixed RUN level (tests).
	SetConfig(cfg BKConfig) error
	// InstallSlot builds fresh inner maps for slot and publishes them in
	// the slot tables. A failure leaves the slot unpublished (never half
	// installed).
	InstallSlot(slot uint32, rules BKSlotRules) error
	// RemoveSlot unpublishes slot and frees its inner maps.
	RemoveSlot(slot uint32) error
	// SetCgroupPolicy writes (or replaces, atomically) a cgroup's entry.
	SetCgroupPolicy(cgroupID uint64, p BKCgroupPolicy) error
	// DeleteCgroupPolicy removes a cgroup's entry (idempotent).
	DeleteCgroupPolicy(cgroupID uint64) error
	// StartRingbufReader reads events into the recorder lookup. Events
	// carry their own verdict.
	StartRingbufReader(ctx context.Context, lookupRecorder func(cgroupID uint64) *ViolationRecorder) (stop func(), err error)
	// Close releases the program and maps (not the cgroup links).
	Close() error
}

// BuildKitPlatform is implemented by platforms that can load the
// egress_bk object. Optional: a Platform without it gets the legacy
// audit-only attach.
type BuildKitPlatform interface {
	LoadBuildKitEBPF(trustedCIDRs []net.IPNet) (BuildKitDatapath, error)
}

// ActionForVerdict maps an egress_bk event verdict (and, for blocked
// connections, the drop reason) to a Violation action. The verdict is
// the authority: nothing here consults a global mode.
func ActionForVerdict(verdict, reason uint8) string {
	switch verdict {
	case bkVerdictDropped:
		if reason == dropReasonSinkhole {
			return "sinkhole_hit"
		}

		if reason == dropReasonDNSBypass {
			return "dns_bypass_dropped"
		}

		return "packet_dropped"
	case bkVerdictWouldBlock:
		return "would_block"
	case bkVerdictAllowed:
		return "packet_allowed"
	default:
		// bkVerdictObserved and anything unknown: the packet passed.
		return "packet_observed"
	}
}

// decodeBKEvent decodes one egress_bk ringbuf record. ok is false for a
// short record or one from a kernel context (pid 0) that carries no
// attribution.
func decodeBKEvent(raw []byte, now time.Time) (Violation, uint8, bool) {
	if len(raw) < minBKDropEventSize {
		return Violation{}, 0, false
	}

	pid := binary.LittleEndian.Uint32(raw[16:20])
	if pid == 0 {
		return Violation{}, 0, false
	}

	reason := raw[15]
	verdict := raw[292]
	state := raw[293]

	v := Violation{
		IP:         net.IPv4(raw[0], raw[1], raw[2], raw[3]).String(),
		Port:       int(binary.LittleEndian.Uint16(raw[4:6])),
		PID:        pid,
		Comm:       cString(raw[20:36]),
		BinaryPath: cString(raw[36:292]),
		Timestamp:  now,
		Action:     ActionForVerdict(verdict, reason),
		CgroupID:   binary.LittleEndian.Uint64(raw[7:15]),
	}

	if reason == dropReasonIPv6 {
		v.IP = "::"
	}

	switch state {
	case bkStatePending:
		v.EnforcementState = EnfStatePendingBind
	case bkStateDegradedLevel:
		v.EnforcementState = EnfStateDegradedLevel
		v.DegradedReason = DegradedRunLevel
	}

	return v, state, true
}

// cString returns buf up to the first NUL.
func cString(buf []byte) string {
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		return string(buf[:i])
	}

	return string(buf)
}
