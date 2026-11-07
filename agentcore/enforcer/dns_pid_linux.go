//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Must match struct dns_pid_attribution in dns_pid.c:
// pid(4) + comm(16) + parent_comm(16) + cgroup_id(8) + ts_ns(8) + flags(1) = 53.
const (
	dnsPIDAttrSize       = 53
	attrOffsetPID        = 0
	attrOffsetComm       = 4
	attrOffsetParentComm = 20
	attrOffsetCgroupID   = 36

	binaryPathLen = 256
)

// dnsAttrKeySize matches sizeof(struct dns_attr_key) in dns_pid.c:
// u64 netns_cookie (8) + u16 src_port (2) + 6B padding = 16B.
const dnsAttrKeySize = 16

// processInfoSize = binary_path(256) + exec_ts(8) + cgroup_id(8) + exec_id(8) = 280.
// Must match struct process_info in dns_pid.c and processInfoEntry below.
const processInfoSize = binaryPathLen + 8 + 8 + 8

// verifyDnspidBytecode asserts that the three structs this file decodes
// via byte offsets still have the sizes the userspace code assumes. See
// verifyStructSize (btf_verify.go) for why this exists.
func verifyDnspidBytecode() error {
	spec, err := loadDnspid()
	if err != nil {
		return fmt.Errorf("load dns_pid spec: %w", err)
	}

	checks := []struct {
		name string
		size uint32
	}{
		{"dns_pid_attribution", dnsPIDAttrSize},
		{"dns_attr_key", dnsAttrKeySize},
		{"process_info", processInfoSize},
	}

	for _, c := range checks {
		verifyErr := verifyStructSize(spec.Types, c.name, c.size)
		if verifyErr != nil {
			return verifyErr
		}
	}

	return nil
}

// encodeDNSAttrKey produces a 16-byte little-endian key matching the
// C struct byte-for-byte. We marshal as a fixed array rather than a Go
// struct because encoding/binary (which cilium/ebpf uses for struct
// keys under the hood) silently skips blank `_` padding fields, which
// would produce a 10-byte key and miss every lookup. Byte array is
// unambiguous on both sides.
func encodeDNSAttrKey(netnsCookie uint64, srcPort uint16) [dnsAttrKeySize]byte {
	var key [dnsAttrKeySize]byte
	binary.LittleEndian.PutUint64(key[0:8], netnsCookie)
	binary.LittleEndian.PutUint16(key[8:10], srcPort)
	// bytes 10..15 are zero (array default) — matches C struct's
	// implicit/explicit padding initialised to zero.
	return key
}

// processInfoEntry matches struct process_info in dns_pid.c (packed 280 B):
// binary_path(256) + exec_ts(8) + cgroup_id(8) + exec_id(8).
type processInfoEntry struct {
	BinaryPath [binaryPathLen]byte
	ExecTs     uint64
	CgroupID   uint64
	ExecID     uint64
}

// DNSPIDTracker populates src_port → (pid, comm, parent_comm, cgroup_id)
// via kprobes on udp_sendmsg / tcp_connect, and pid → binary_path via a
// BPF LSM program (primary) + sched_process_exec tracepoint (fallback).
// The DNS proxy reads both maps synchronously via bpf syscalls when it
// handles each query, so attribution is race-free by construction:
// the kprobe runs strictly before the packet leaves the kernel, and
// the proxy's lookup strictly after the packet arrives at its socket.
type DNSPIDTracker struct {
	objs   *dnspidObjects
	links  []link.Link
	logger *slog.Logger
}

// NewDNSPIDTracker loads the BPF objects and attaches the probes.
// Close() must be called on shutdown.
func NewDNSPIDTracker(logger *slog.Logger) (*DNSPIDTracker, error) {
	verifyErr := verifyDnspidBytecode()
	if verifyErr != nil {
		return nil, fmt.Errorf("dns_pid bytecode verify: %w", verifyErr)
	}

	var objs dnspidObjects

	loadErr := loadDnspidObjectsTolerant(&objs, logger)
	if loadErr != nil {
		return nil, fmt.Errorf("load dns_pid bpf objects: %w", loadErr)
	}

	tracker := &DNSPIDTracker{objs: &objs, logger: logger}

	// fexit/udp_sendmsg (not kprobe/udp_sendmsg): autobind for unconnected
	// UDP happens inside udp_sendmsg, so at entry sk->skc_num is still 0.
	// At fexit, the port is committed and attribution captures correctly
	// for glibc's sendto()-based DNS path. See dns_pid.c for details.
	udp, err := link.AttachTracing(link.TracingOptions{Program: objs.DnsPidSendmsg})
	if err != nil {
		tracker.Close()

		return nil, fmt.Errorf("attach fexit udp_sendmsg: %w", err)
	}

	tracker.links = append(tracker.links, udp)

	tcp, err := link.Kprobe("tcp_connect", objs.DnsPidTcpConnect, nil)
	if err != nil {
		tracker.Close()

		return nil, fmt.Errorf("attach kprobe tcp_connect: %w", err)
	}

	tracker.links = append(tracker.links, tcp)

	// binary_path sources: LSM primary + tracepoint fallback. Both are
	// best-effort. DnsPidBprm is nil if the LSM program failed to
	// verify on this kernel (see loadDnspidObjectsTolerant).
	lsmAttached := false

	if objs.DnsPidBprm != nil {
		bprm, bprmErr := link.AttachLSM(link.LSMOptions{Program: objs.DnsPidBprm})
		if bprmErr != nil {
			logger.Info("dns_pid LSM (bprm_committed_creds) unavailable, falling back to tracepoint for binary_path",
				"error", bprmErr)
		} else {
			tracker.links = append(tracker.links, bprm)
			lsmAttached = true
		}
	}

	exec, execErr := link.Tracepoint("sched", "sched_process_exec", objs.DnsPidExec, nil)
	switch {
	case execErr == nil:
		tracker.links = append(tracker.links, exec)
	case lsmAttached:
		// LSM is handling binary_path; the tracepoint is redundant.
		// Downgrade to Debug so Talos hosts (no tracefs mount) don't
		// emit a misleading Warn in every agent log line.
		logger.Debug("dns_pid sched_process_exec tracepoint unavailable (LSM handles binary_path)",
			"error", execErr)
	default:
		logger.Warn("dns_pid sched_process_exec tracepoint failed and LSM is unavailable — binary_path attribution will be empty",
			"error", execErr)
	}

	// Drop process_info entries on process exit so a recycled pid cannot
	// inherit a previous process's binary_path. Best-effort: without it
	// the map still works, bounded by LRU, with the original staleness
	// risk.
	if objs.DnsPidExit != nil {
		exit, exitErr := link.Tracepoint("sched", "sched_process_exit", objs.DnsPidExit, nil)
		if exitErr != nil {
			logger.Debug("dns_pid sched_process_exit tracepoint unavailable", "error", exitErr)
		} else {
			tracker.links = append(tracker.links, exit)
		}
	}

	// Seed process_info for pre-existing processes. The path is the
	// agent's host-namespace view of /proc/<pid>/exe (overlay path for
	// container processes), so it's a placeholder — it gets overwritten
	// with a canonical container-relative path the next time that pid
	// exec()s. In CI the window is short.
	seedExistingProcesses(objs.ProcessInfo, logger)

	return tracker, nil
}

// loadDnspidObjectsTolerant loads the BPF objects with graceful fallback:
// if BPF LSM isn't available on the target kernel (CONFIG_BPF_LSM=n, bpf
// missing from the `lsm=` cmdline list, or the LSM program itself fails
// the verifier's bpf_d_path pointer-trust checks), it loads the spec
// without the LSM program and falls through to the sched_process_exec
// tracepoint for binary_path. Without this fallback, any environmental
// mismatch would kill the entire DNS PID tracker — no pid, no comm, no
// attribution at all.
//
// Detection: try the full typed load with the LSM program. If it
// fails with a fallbackable error (verifier rejection of the bprm
// program, ENOTSUP / EOPNOTSUPP from the LSM attach syscall), retry
// without the LSM program. Anything else propagates.
//
// Why no sysfs pre-check: an earlier iteration read
// /sys/kernel/security/lsm to pre-check whether bpf was in the
// enabled list. That file is absent on Talos (securityfs isn't
// exposed in the agent's filesystem view), but BPF LSM is enabled
// and working on Talos — our sock_attr LSM programs in egress.c
// attach and fire correctly there. The pre-check was producing false
// negatives: "LSM unavailable" reports on kernels where LSM actually
// worked, which silently disabled dns_pid's binary_path capture on
// production Talos. The try-and-catch pattern here is strictly more
// correct than sysfs probing and matches what attachSockAttrLSM
// already does on the egress side.
func loadDnspidObjectsTolerant(objs *dnspidObjects, logger *slog.Logger) error {
	spec, err := loadDnspid()
	if err != nil {
		return err
	}

	// Fast path: full typed load including the LSM program.
	loadErr := spec.LoadAndAssign(objs, nil)
	if loadErr == nil {
		return nil
	}

	// Bucket the error — verifier rejection of the LSM program or
	// ENOTSUP at the syscall boundary both warrant fallback; anything
	// else is a real failure.
	if !isLSMFallbackable(loadErr) {
		return fmt.Errorf("load dnspid spec: %w", loadErr)
	}

	logger.Info("dns_pid LSM program failed to load on this kernel; "+
		"reloading without it — binary_path will come from the "+
		"sched_process_exec tracepoint fallback instead",
		"error", loadErr)

	return loadWithoutLSM(objs)
}

// loadWithoutLSM loads the dnspid spec with the LSM program stripped.
// Used when BPF LSM isn't available (pre-check) or when the LSM program
// specifically failed verification (fallback). hand-populates objs by
// SEC name rather than maintaining a parallel LSM-less typed struct —
// the field list here is the single place that must stay in sync with
// dns_pid.c's SEC() names.
func loadWithoutLSM(objs *dnspidObjects) error {
	spec, err := loadDnspid()
	if err != nil {
		return err
	}

	delete(spec.Programs, "dns_pid_bprm")

	coll, collErr := ebpf.NewCollection(spec)
	if collErr != nil {
		return fmt.Errorf("reload without LSM: %w", collErr)
	}

	objs.DnsPidSendmsg = coll.Programs["dns_pid_sendmsg"]
	objs.DnsPidTcpConnect = coll.Programs["dns_pid_tcp_connect"]
	objs.DnsPidExec = coll.Programs["dns_pid_exec"]
	objs.DnsPidExit = coll.Programs["dns_pid_exit"]
	objs.DnsKnownCgroups = coll.Maps["dns_known_cgroups"]
	objs.DnsRunParents = coll.Maps["dns_run_parents"]
	objs.DnsPidAttribution = coll.Maps["dns_pid_attribution"]
	objs.ProcessInfo = coll.Maps["process_info"]

	return nil
}

// isLSMFallbackable returns true when err should trigger the
// tracepoint-only fallback rather than a hard agent failure. Two
// buckets count:
//
//  1. *ebpf.VerifierError on the dns_pid_bprm program. The bpf_d_path
//     helper has kernel-version-dependent pointer-trust behaviour that
//     can reject even correct-looking programs on some kernels.
//
//  2. ENOTSUP / EOPNOTSUPP at the syscall boundary. Happens on kernels
//     where /sys/kernel/security/lsm claims bpf is present but the
//     specific attach fails (unusual but observed on container-host
//     setups with partial LSM config).
//
// All other errors are real — propagate so operators see them and fix
// the root cause rather than getting a silent degradation.
func isLSMFallbackable(err error) bool {
	if err == nil {
		return false
	}

	// Typed verifier error: program name identifies it as the LSM program.
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && strings.Contains(ve.Error(), "dns_pid_bprm") {
		return true
	}

	// Syscall-level rejection of an LSM attach.
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return true
	}

	return false
}

// seedExistingProcesses walks /proc and populates process_info for
// every running process with a readable /proc/<pid>/exe.
func seedExistingProcesses(m *ebpf.Map, logger *slog.Logger) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Warn("process_info seed: read /proc failed, pre-existing processes won't have binary_path", "error", err)

		return
	}

	var (
		candidates int
		seeded     int
	)

	for _, e := range entries {
		pidU, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}

		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}

		candidates++

		var pi processInfoEntry

		copy(pi.BinaryPath[:], exe)

		pid := uint32(pidU)

		putErr := m.Put(pid, pi)
		if putErr == nil {
			seeded++
		}
	}

	// Info-level: operators care about this at agent start. A big gap
	// between candidates and seeded hints at map-capacity issues.
	logger.Info("process_info seeded", "seeded", seeded, "candidates", candidates)
}

// AddCgroup registers a container's cgroup ID for tracking.
func (t *DNSPIDTracker) AddCgroup(cgroupPath string) (uint64, error) {
	var st syscall.Stat_t

	err := syscall.Stat(cgroupPath, &st)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}

	cgID := st.Ino

	err = t.objs.DnsKnownCgroups.Put(cgID, uint8(1))
	if err != nil {
		return 0, fmt.Errorf("put dns_known_cgroups: %w", err)
	}

	return cgID, nil
}

// RemoveCgroup unregisters a container's cgroup ID.
func (t *DNSPIDTracker) RemoveCgroup(cgroupID uint64) {
	_ = t.objs.DnsKnownCgroups.Delete(cgroupID)
}

// AddRunParent registers a BuildKit parent cgroup: DNS queries from any
// task below it are tracked and attributed to the RUN cgroup (the
// parent's child on the task's path), which Lookup then returns as the
// cgroup id. dns_known_cgroups holds exact ids only, so RUN cgroups that
// come and go per build step need this subtree form.
func (t *DNSPIDTracker) AddRunParent(cgroupID uint64) error {
	if err := t.objs.DnsRunParents.Put(cgroupID, uint8(1)); err != nil {
		return fmt.Errorf("put dns_run_parents: %w", err)
	}

	return nil
}

// RemoveRunParent unregisters a BuildKit parent cgroup (idempotent).
func (t *DNSPIDTracker) RemoveRunParent(cgroupID uint64) {
	_ = t.objs.DnsRunParents.Delete(cgroupID)
}

// Lookup returns the PID, comm, parent comm, and cgroup ID for a DNS
// query from netnsCookie:srcPort. Returns zero values on miss.
// netnsCookie is obtained userspace-side via getsockopt(SO_NETNS_COOKIE)
// on a socket bound in the container netns — see
// (*DNSProxy).netnsCookieFromConn.
func (t *DNSPIDTracker) Lookup(netnsCookie uint64, srcPort uint16) (uint32, string, string, uint64) {
	if srcPort == 0 {
		return 0, "", "", 0
	}

	key := encodeDNSAttrKey(netnsCookie, srcPort)

	var raw [dnsPIDAttrSize]byte

	err := t.objs.DnsPidAttribution.Lookup(key, &raw)
	if err != nil {
		if t.logger != nil {
			t.logger.Debug("dns pid lookup miss",
				"cookie", netnsCookie, "port", srcPort, "err", err)
		}

		return 0, "", "", 0
	}

	return binary.LittleEndian.Uint32(raw[attrOffsetPID : attrOffsetPID+4]),
		nullTerminated(raw[attrOffsetComm : attrOffsetComm+16]),
		nullTerminated(raw[attrOffsetParentComm : attrOffsetParentComm+16]),
		binary.LittleEndian.Uint64(raw[attrOffsetCgroupID : attrOffsetCgroupID+8])
}

// BinaryPathForPID returns the canonical binary path for pid, or "" on
// miss. Used by the packet ringbuf reader to attribute drop_events that
// carry only a pid (no src_port) — complements Lookup which is DNS-proxy-
// side and keyed on (netns_cookie, src_port). Nil receiver is a safe
// no-op for tests.
//
// Known edge case: the process_info map has no TTL beyond LRU (16k
// entries). On hosts that cycle through more than 16k pids during a
// single job, entries age out and BinaryPathForPID returns "" for
// still-live processes — acceptable degradation. The inverse case —
// pid recycling collisions reusing a stale map entry — would require
// >pid_max process creations (default 4M on 64-bit) during a single
// bucket window, which doesn't happen on realistic CI workloads. If
// this ever becomes a concern, compare pi.ExecTs against a freshness
// threshold derived from CLOCK_MONOTONIC.
func (t *DNSPIDTracker) BinaryPathForPID(pid uint32) string {
	if t == nil || t.objs == nil || pid == 0 {
		return ""
	}

	var pi processInfoEntry

	err := t.objs.ProcessInfo.Lookup(pid, &pi)
	if err != nil {
		return ""
	}

	return nullTerminated(pi.BinaryPath[:])
}

// LookupWithBinary is Lookup plus the binary_path field. Binary path is
// fetched with a second BPF map read against process_info[pid]; missing
// binary_path is returned as an empty string (pid/comm/... still valid).
func (t *DNSPIDTracker) LookupWithBinary(netnsCookie uint64, srcPort uint16) (uint32, string, string, string, uint64) {
	pid, comm, parentComm, cgroupID := t.Lookup(netnsCookie, srcPort)
	if pid == 0 {
		return 0, "", "", "", 0
	}

	var (
		binaryPath string
		pi         processInfoEntry
	)

	lookupErr := t.objs.ProcessInfo.Lookup(pid, &pi)
	if lookupErr == nil {
		binaryPath = nullTerminated(pi.BinaryPath[:])
	}

	return pid, comm, parentComm, binaryPath, cgroupID
}

// Close releases kprobes and frees BPF resources.
func (t *DNSPIDTracker) Close() {
	for _, lnk := range t.links {
		_ = lnk.Close()
	}

	if t.objs != nil {
		t.objs.Close() //nolint:errcheck,gosec // cleanup
	}
}
