//go:build linux

package enforcer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/nftables"
)

// minDropEventSize = dst_ip(4) + dst_port(2) + protocol(1) + cgroup_id(8) +
// reason(1) + pid(4) + comm(16) + binary_path(256) = 292.
// binary_path comes from sk_storage populated at LSM socket_connect (or
// from bpf_get_current_* fallback for sockets that predate agent attach).
const minDropEventSize = 292

// sockOwnerSize matches struct sock_owner in egress.c:
// cgroup_id(8) + pid(4) + _reserved(4) + comm(16) + binary_path(256) = 288.
// Declared here for the BTF self-check at LoadEBPF time.
const sockOwnerSize = 288

// actionForDrop maps a drop event's reason byte + mode to a Violation
// Action string. Sinkhole is only distinguished in block mode —
// audit-mode hits appear as plain packet_observed since the connection
// was allowed through (sinkhole-specific signals require the packet to
// be dropped to be meaningful).
func actionForDrop(reason uint8, auditMode bool) string {
	if auditMode {
		return "packet_observed"
	}

	if reason == dropReasonSinkhole {
		return "sinkhole_hit"
	}

	return "packet_dropped"
}

var errNotUDPConn = errors.New("dial returned non-UDP conn")

// LinuxPlatform is the production Platform using eBPF, netns, and nftables.
type LinuxPlatform struct {
	Logger *slog.Logger
}

// GetCgroupPath returns the cgroupv2 path for a process.
func (p *LinuxPlatform) GetCgroupPath(pid int) (string, error) {
	return getCgroupPath(pid)
}

// NetnsInode returns the inode of /proc/<pid>/ns/net.
func (p *LinuxPlatform) NetnsInode(pid int) (uint64, error) {
	var st syscall.Stat_t

	err := syscall.Stat(fmt.Sprintf("/proc/%d/ns/net", pid), &st)
	if err != nil {
		return 0, fmt.Errorf("stat netns for pid %d: %w", pid, err)
	}

	return st.Ino, nil
}

// BindInNetns binds UDP and TCP listeners inside the container network namespace.
func (p *LinuxPlatform) BindInNetns(pid int, listenAddr string) (net.PacketConn, net.Listener, error) {
	var udpConn net.PacketConn

	var tcpListener net.Listener

	lc := net.ListenConfig{}

	err := inNetns(pid, func() error {
		var bindErr error

		udpConn, bindErr = lc.ListenPacket(context.Background(), "udp4", listenAddr)
		if bindErr != nil {
			return fmt.Errorf("bind udp: %w", bindErr)
		}

		tcpListener, bindErr = lc.Listen(context.Background(), "tcp4", listenAddr)
		if bindErr != nil {
			udpConn.Close() //nolint:errcheck,gosec // cleanup

			return fmt.Errorf("bind tcp: %w", bindErr)
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return udpConn, tcpListener, nil
}

// SetupDNSRedirect configures nftables DNS redirect rules in the container network namespace.
func (p *LinuxPlatform) SetupDNSRedirect(pid int) error {
	return inNetns(pid, func() error {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("create nftables conn: %w", err)
		}

		return setupDNSRedirect(conn)
	})
}

// RemoveDNSRedirect removes nftables DNS redirect rules from the container network namespace.
func (p *LinuxPlatform) RemoveDNSRedirect(pid int) error {
	err := inNetns(pid, func() error {
		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("create nftables conn: %w", err)
		}

		return removeDNSRedirect(conn)
	})
	if err != nil {
		// Best-effort: netns may already be gone when container dies.
		p.Logger.Debug("remove dns redirect", "pid", pid, "error", err)
	}

	return nil
}

// SetupBuildkitDNSFirewall installs host-netns nftables rules to drop off-host
// traffic destined for the BuildKit DNS proxy on port 53. Runs in the agent's
// default (host) netns — nftables.New() with no options binds to the current
// namespace, which is host for the agent process.
func (p *LinuxPlatform) SetupBuildkitDNSFirewall(listenIP net.IP) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("create nftables conn: %w", err)
	}

	return setupBuildkitDNSFirewall(conn, listenIP, p.Logger)
}

// RemoveBuildkitDNSFirewall tears down the host-netns firewall table.
func (p *LinuxPlatform) RemoveBuildkitDNSFirewall() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("create nftables conn: %w", err)
	}

	return removeBuildkitDNSFirewall(conn)
}

// DialUpstreamInNetns creates a marked UDP connection to addr inside the container's netns.
// The SO_MARK prevents nftables from redirecting the proxy's own upstream queries.
func (p *LinuxPlatform) DialUpstreamInNetns(pid int, addr string, mark int) (*net.UDPConn, error) {
	var conn *net.UDPConn

	err := inNetns(pid, func() error {
		d := net.Dialer{
			Control: func(_, _ string, c syscall.RawConn) error {
				var sErr error

				ctlErr := c.Control(func(fd uintptr) {
					sErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) //nolint:gosec // fd fits int on 64-bit Linux
				})
				if ctlErr != nil {
					return fmt.Errorf("raw control: %w", ctlErr)
				}

				if sErr != nil {
					return fmt.Errorf("set SO_MARK: %w", sErr)
				}

				return nil
			},
		}

		nc, dialErr := d.DialContext(context.Background(), "udp4", addr)
		if dialErr != nil {
			return fmt.Errorf("dial marked udp: %w", dialErr)
		}

		udpConn, ok := nc.(*net.UDPConn)
		if !ok {
			nc.Close() //nolint:errcheck,gosec // cleanup

			return errNotUDPConn
		}

		conn = udpConn

		return nil
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// LoadEBPF loads the eBPF egress filter program and maps (without attaching to a cgroup).
//
// The LSM hooks (sock_attr_connect, sock_attr_sendmsg) live in a
// process-singleton bundle (linuxLSMHandle). The egress collection
// loaded here is wired to that singleton's sock_owners map via
// CollectionOptions.MapReplacements — without map-sharing, the LSM
// captures would land in one kernel map and the egress reads would
// hit another, so attribution would silently break. Singleton-sharing
// also bounds the per-syscall cost: LSM programs are stackable, so a
// per-pod attach would run N copies of the same hook on every
// host-wide socket syscall.
//
// Sub-step timings are emitted via a "load_ebpf detail" Info log so
// operators can profile per-pod attach cost without exec'ing into pods.
func (p *LinuxPlatform) LoadEBPF(auditMode bool, trustedCIDRs []net.IPNet) (EBPFHandle, error) {
	stepStart := time.Now()

	// Singleton LSM bundle: load + attach once per process. Subsequent
	// LoadEBPF calls reuse the same handle. Failure here is non-fatal —
	// degraded mode means egress falls back to bpf_get_current_*, which
	// is softirq-prone but doesn't block enforcement on kernels without
	// bpf-lsm support.
	lsm, lsmErr := ensureLSMSingleton(p.Logger)
	if lsmErr != nil {
		p.Logger.Warn("sock_attr LSM singleton unavailable; packet attribution "+
			"will fall back to current (softirq-prone) path",
			"error", lsmErr)
	}

	lsmAttachMs := time.Since(stepStart).Milliseconds()
	stepStart = time.Now()

	spec, err := loadEbpf()
	if err != nil {
		return nil, fmt.Errorf("load ebpf spec: %w", err)
	}

	specMs := time.Since(stepStart).Milliseconds()
	stepStart = time.Now()

	verifyErr := verifyStructSize(spec.Types, "drop_event", minDropEventSize)
	if verifyErr != nil {
		return nil, fmt.Errorf("egress bytecode verify: %w", verifyErr)
	}

	verifyErr = verifyStructSize(spec.Types, "sock_owner", sockOwnerSize)
	if verifyErr != nil {
		return nil, fmt.Errorf("egress bytecode verify: %w", verifyErr)
	}

	verifyMs := time.Since(stepStart).Milliseconds()
	stepStart = time.Now()

	var objs ebpfObjects

	// Wire the per-pod egress collection to the singleton sock_owners
	// map. The egress program reads o->cgroup_id / o->pid / o->binary_path
	// via bpf_sk_storage_get; a fresh per-pod allocation would mean LSM
	// captures land in one map and egress reads from another, breaking
	// attribution.
	var collOpts *ebpf.CollectionOptions
	if lsm != nil {
		collOpts = &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"sock_owners": lsm.SockOwners,
			},
		}
	}

	err = spec.LoadAndAssign(&objs, collOpts)
	if err != nil {
		return nil, fmt.Errorf("load ebpf objects: %w", err)
	}

	loadAssignMs := time.Since(stepStart).Milliseconds()
	stepStart = time.Now()

	var mode uint8
	if auditMode {
		mode = 1
	}

	err = objs.Config.Put(uint32(0), mode)
	if err != nil {
		objs.Close() //nolint:errcheck,gosec // cleanup on error path

		return nil, fmt.Errorf("set config map: %w", err)
	}

	// Populate trusted CIDRs LPM trie.
	cidrPuts := 0

	for _, cidr := range trustedCIDRs {
		ones, _ := cidr.Mask.Size()
		ip4 := cidr.IP.To4()

		if ip4 == nil {
			continue // skip IPv6 CIDRs
		}

		key := packLPMKey(ip4, ones)

		putErr := objs.TrustedNets.Put(key[:], uint8(1))
		if putErr != nil {
			p.Logger.Error("put trusted_nets", "cidr", cidr.String(), "error", putErr)
		}

		cidrPuts++
	}

	postLoadMs := time.Since(stepStart).Milliseconds()

	p.Logger.Info("load_ebpf detail",
		"spec_parse_ms", specMs,
		"btf_verify_ms", verifyMs,
		"load_assign_ms", loadAssignMs,
		"lsm_attach_ms", lsmAttachMs, // amortizes to ~0 after first call
		"post_load_ms", postLoadMs,
		"cidrs_loaded", cidrPuts,
		"lsm_singleton", lsm != nil,
	)

	return &linuxEBPFHandle{
		objs:   &objs,
		logger: p.Logger,
		lsm:    lsm,
	}, nil
}

// CgroupID returns the inode number of a cgroup directory.
func (p *LinuxPlatform) CgroupID(cgroupPath string) (uint64, error) {
	var st syscall.Stat_t

	err := syscall.Stat(cgroupPath, &st)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}

	return st.Ino, nil
}

// packLPMKey encodes an IPv4 CIDR as an 8-byte LPM trie key: [prefixlen u32][ip u32].
func packLPMKey(ip4 net.IP, prefixLen int) [8]byte {
	var key [8]byte

	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen)) //nolint:gosec // prefix length is 0-32, safe
	copy(key[4:8], ip4)

	return key
}

// linuxEBPFHandle wraps the real eBPF objects for one per-pod egress
// collection. The LSM bundle (sock_owners + sock_known_cgroups + LSM
// programs) is the process-singleton at `lsm`; this handle does not own
// it and must not Close it.
type linuxEBPFHandle struct {
	objs   *ebpfObjects
	logger *slog.Logger
	lsm    *linuxLSMHandle // process-singleton; nil in degraded mode
}

// linuxCgroupLink wraps a single cgroup attachment.
type linuxCgroupLink struct {
	link link.Link
}

func (l *linuxCgroupLink) Close() error {
	if l.link != nil {
		err := l.link.Close()
		if err != nil {
			return fmt.Errorf("close cgroup link: %w", err)
		}
	}

	return nil
}

func (h *linuxEBPFHandle) AttachCgroup(cgroupPath string) (CgroupLink, error) {
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: h.objs.EgressFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("attach cgroup: %w", err)
	}

	return &linuxCgroupLink{link: cgroupLink}, nil
}

func (h *linuxEBPFHandle) AddAllowedIP(ip net.IP, ports []int) error {
	for _, port := range ports {
		key := PackAllowKey(ip, port)

		putErr := h.objs.AllowedIps.Put(key[:], uint8(1))
		if putErr != nil {
			h.logger.Error("put allow map", "ip", ip, "port", port, "error", putErr)

			return fmt.Errorf("put allow map: %w", putErr)
		}
	}

	return nil
}

func (h *linuxEBPFHandle) AddDeniedIP(ip net.IP, port int) error {
	key := PackAllowKey(ip, port)

	putErr := h.objs.DeniedIps.Put(key[:], uint8(1))
	if putErr != nil {
		h.logger.Error("put deny map", "ip", ip, "port", port, "error", putErr)

		return fmt.Errorf("put deny map: %w", putErr)
	}

	return nil
}

func (h *linuxEBPFHandle) RemoveDeniedIP(ip net.IP, port int) error {
	key := PackAllowKey(ip, port)

	delErr := h.objs.DeniedIps.Delete(key[:])
	if delErr != nil {
		// ENOENT is expected when callers double-remove; only complain
		// about other errors. The cilium/ebpf wrapper does not export a
		// distinct error type for missing keys, so the cheapest check
		// is a substring match against the kernel's wording.
		if errors.Is(delErr, ebpf.ErrKeyNotExist) {
			return nil
		}

		h.logger.Error("delete deny map", "ip", ip, "port", port, "error", delErr)

		return fmt.Errorf("delete deny map: %w", delErr)
	}

	return nil
}

func (h *linuxEBPFHandle) SetMode(audit bool) error {
	var mode uint8
	if audit {
		mode = 1
	}

	err := h.objs.Config.Put(uint32(0), mode)
	if err != nil {
		return fmt.Errorf("update ebpf config map: %w", err)
	}

	return nil
}

func (h *linuxEBPFHandle) ReadStats() int64 {
	var values []uint64

	err := h.objs.Stats.Lookup(uint32(0), &values)
	if err != nil {
		return 0
	}

	var total int64
	for _, v := range values {
		total += int64(v) //nolint:gosec // stats counter won't overflow int64
	}

	return total
}

func (h *linuxEBPFHandle) StartRingbufReader(
	ctx context.Context,
	lookupRecorder func(cgroupID uint64) *ViolationRecorder,
	auditMode *atomic.Bool,
) (func(), error) {
	reader, err := ringbuf.NewReader(h.objs.DropEvents)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)

	// Closer goroutine: unblocks reader.Read() when cancelled.
	wg.Go(func() {
		<-ctx.Done()
		reader.Close() //nolint:errcheck,gosec // cleanup
	})

	// Reader goroutine: processes drop events until reader is closed.
	wg.Go(func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}

				h.logger.Debug("ringbuf read error", "error", err)

				continue
			}

			if len(record.RawSample) < minDropEventSize {
				continue
			}

			var ev dropEvent
			copy(ev.DstIP[:], record.RawSample[0:4])
			copy(ev.DstPort[:], record.RawSample[4:6])
			ev.Protocol = record.RawSample[6]
			ev.CgroupID = binary.LittleEndian.Uint64(record.RawSample[7:15])
			ev.Reason = record.RawSample[15]
			ev.PID = binary.LittleEndian.Uint32(record.RawSample[16:20])
			copy(ev.Comm[:], record.RawSample[20:36])
			copy(ev.BinaryPath[:], record.RawSample[36:292])

			recorder := lookupRecorder(ev.CgroupID)
			if recorder == nil {
				continue
			}

			ip := net.IPv4(ev.DstIP[0], ev.DstIP[1], ev.DstIP[2], ev.DstIP[3])
			port := int(binary.LittleEndian.Uint16(ev.DstPort[:]))

			action := actionForDrop(ev.Reason, auditMode.Load())

			// Defense in depth for softirq-context events that bypass
			// the PF_KTHREAD filter in egress.c's skip_softirq_attribution
			// (e.g. a softirq preempting a user task — PF_KTHREAD is
			// clear but attribution is still meaningless). pid == 0 is
			// the universal "kernel context" marker — it covers swapper
			// (per-CPU idle, pid 0 by definition) and any helper that
			// runs without a real task. Maintaining a comm-prefix list
			// of kernel-thread names would just be the original "bolted
			// on" anti-pattern in a different shape.
			comm := nullTerminated(ev.Comm[:])
			if ev.PID == 0 {
				continue
			}

			// binary_path comes exclusively from sk_storage (populated at
			// LSM socket_connect via bpf_d_path on task->mm->exe_file).
			// We deliberately do NOT fall back to process_info — that
			// would re-introduce a dependency on dns_pid.c's LRU map
			// and break the "agent is self-contained for packet
			// attribution" property. An empty binary_path here means
			// the socket was opened before sk_storage capture was
			// active (pre-attach race or LSM unavailable); the
			// integration tests assert this is rare enough to be a
			// canary condition rather than a steady-state fallback.
			binaryPath := nullTerminated(ev.BinaryPath[:])

			v := Violation{
				IP:         ip.String(),
				Port:       port,
				PID:        ev.PID,
				Comm:       comm,
				BinaryPath: binaryPath,
				Timestamp:  time.Now(),
				Action:     action,
			}

			// Stamp BuildKit step attribution if the event's cgroup
			// is a runc RUN container bound to a vertex by the
			// cgroup-join layer. No-op when the BuildKit subscriber
			// isn't installed or the cgroup isn't tracked (the
			// common case for non-BuildKit egress).
			if binding, ok := LookupBuildKitBinding(ev.CgroupID); ok {
				v.BuildSessionRef = binding.SessionRef
				v.BuildVertexDigest = binding.VertexDigest
				v.BuildVertexName = binding.VertexName
				v.BuildAmbiguous = binding.Ambiguous
				v.BuildAmbiguousCandidates = binding.AmbiguousCandidates
			}

			recorder.RecordViolation(v)
		}
	})

	stop := func() {
		cancel()
		wg.Wait() // Wait for both goroutines to exit before returning.
	}

	return stop, nil
}

// Close releases this per-pod egress collection. The singleton LSM
// bundle (sock_owners, sock_known_cgroups, LSM programs) survives —
// see ShutdownSentinelLSM for that lifecycle.
func (h *linuxEBPFHandle) Close() error {
	if h.objs != nil {
		return h.objs.Close()
	}

	return nil
}

// AddSockKnownCgroup registers a container cgroup with the singleton
// sock_attr LSM filter so its sockets populate sk_storage. Called from
// mgr.Attach.
func (h *linuxEBPFHandle) AddSockKnownCgroup(cgroupID uint64) error {
	if h.lsm == nil {
		return nil // degraded mode: LSM unavailable
	}

	return h.lsm.AddSockKnownCgroup(cgroupID)
}

// RemoveSockKnownCgroup unregisters a container cgroup from the singleton
// LSM filter. Existing sk_storage entries for that cgroup's sockets stay
// valid until the kernel destroys each socket — idempotent and cleans
// up naturally.
func (h *linuxEBPFHandle) RemoveSockKnownCgroup(cgroupID uint64) {
	if h.lsm == nil {
		return
	}

	h.lsm.RemoveSockKnownCgroup(cgroupID)
}

// linuxLSMHandle owns the process-singleton sock_attr bundle: the loaded
// LSM programs (sock_attr_connect, sock_attr_sendmsg), the SK_STORAGE
// sock_owners map (read by every per-pod egress program), and the
// sock_known_cgroups HASH map (the host-wide filter that decides which
// sockets get sk_storage allocation).
//
// One instance per agent process. See ensureLSMSingleton for lifecycle.
type linuxLSMHandle struct {
	objs       *sockAttrObjects
	links      []link.Link
	SockOwners *ebpf.Map // re-exposed for MapReplacements wiring
	logger     *slog.Logger
}

// AddSockKnownCgroup registers a cgroup_id with the LSM filter.
// Returns nil if the SockKnownCgroups map is unavailable (defensive —
// shouldn't happen once the singleton is loaded).
func (h *linuxLSMHandle) AddSockKnownCgroup(cgroupID uint64) error {
	if h.objs == nil || h.objs.SockKnownCgroups == nil {
		return nil
	}

	err := h.objs.SockKnownCgroups.Put(cgroupID, uint8(1))
	if err != nil {
		return fmt.Errorf("put sock_known_cgroups: %w", err)
	}

	return nil
}

// RemoveSockKnownCgroup unregisters a cgroup_id. Idempotent.
func (h *linuxLSMHandle) RemoveSockKnownCgroup(cgroupID uint64) {
	if h.objs == nil || h.objs.SockKnownCgroups == nil {
		return
	}

	_ = h.objs.SockKnownCgroups.Delete(cgroupID)
}

// Close releases the LSM links and the loaded objects. Production code
// should call this only via ShutdownSentinelLSM at agent shutdown — the
// kernel reaps everything on process exit, so explicit close is mainly
// for tests that want to verify reload behavior.
func (h *linuxLSMHandle) Close() error {
	for _, l := range h.links {
		_ = l.Close()
	}

	if h.objs != nil {
		return h.objs.Close()
	}

	return nil
}

// LSM singleton state. lsmHandleP is shared across every LinuxPlatform
// in the process — both cmd/agent/main.go's enforcer platform and its
// buildkit platform funnel through the same kernel-side attachments.
//
//nolint:gochecknoglobals // process-level kernel resource — singleton scope is correct.
var (
	lsmMu      sync.Mutex
	lsmHandleP *linuxLSMHandle
)

// ensureLSMSingleton lazily loads + attaches the sock_attr LSM bundle
// once per process on success. Successful loads are cached; failures
// are NOT cached so a transient glitch (e.g. bpf-lsm enabled after
// agent boot) can recover without an agent restart. The trade-off:
// on a kernel that permanently lacks bpf-lsm, every LoadEBPF pays one
// failed-attach syscall — negligible next to the verifier load.
func ensureLSMSingleton(logger *slog.Logger) (*linuxLSMHandle, error) {
	lsmMu.Lock()
	defer lsmMu.Unlock()

	if lsmHandleP != nil {
		return lsmHandleP, nil
	}

	h, err := lsmBundleLoader(logger)
	if err != nil {
		return nil, err
	}

	lsmHandleP = h

	return h, nil
}

// lsmBundleLoader is the function that ensureLSMSingleton calls to
// produce the kernel-side LSM bundle. It's a var (not a direct call to
// loadAndAttachLSM) so that tests can swap in a failure-injecting stub
// to exercise the degraded-mode path without a real kernel without
// bpf-lsm. Production code paths never reassign it.
//
//nolint:gochecknoglobals // test seam, deliberately package-scoped.
var lsmBundleLoader = loadAndAttachLSM

// ShutdownSentinelLSM releases the singleton LSM bundle. Safe to call
// multiple times; safe to call when the singleton was never created.
// Intended for tests + clean agent shutdown; in production the kernel
// reaps on process exit so explicit shutdown is optional.
func ShutdownSentinelLSM() {
	lsmMu.Lock()
	defer lsmMu.Unlock()

	if lsmHandleP == nil {
		return
	}

	_ = lsmHandleP.Close()
	lsmHandleP = nil
}

// loadAndAttachLSM compiles + verifies + attaches the sock_attr bundle.
// Returns a non-nil error only when *all* LSM hooks fail to attach.
// Partial attach (one hook OK, the other fails) returns the handle with
// a Warn log so the agent keeps running with reduced coverage rather
// than failing closed and blocking every pod's enforcement at startup.
func loadAndAttachLSM(logger *slog.Logger) (*linuxLSMHandle, error) {
	spec, err := loadSockAttr()
	if err != nil {
		return nil, fmt.Errorf("load sock_attr spec: %w", err)
	}

	verifyErr := verifyStructSize(spec.Types, "sock_owner", sockOwnerSize)
	if verifyErr != nil {
		return nil, fmt.Errorf("sock_attr bytecode verify: %w", verifyErr)
	}

	var objs sockAttrObjects

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		return nil, fmt.Errorf("load sock_attr objects: %w", err)
	}

	progs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"socket_connect", objs.SockAttrConnect},
		{"socket_sendmsg", objs.SockAttrSendmsg},
	}

	var (
		links []link.Link
		errs  []error
		anyOK bool
	)

	for _, p := range progs {
		if p.prog == nil {
			continue
		}

		lnk, attachErr := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if attachErr != nil {
			errs = append(errs, fmt.Errorf("attach lsm/%s: %w", p.name, attachErr))

			continue
		}

		links = append(links, lnk)
		anyOK = true

		logger.Debug("sock_attr LSM attached (singleton)", "hook", p.name)
	}

	if !anyOK {
		objs.Close() //nolint:errcheck,gosec // cleanup on error path

		return nil, errors.Join(errs...)
	}

	if len(errs) > 0 {
		logger.Warn("some sock_attr LSM hooks failed (partial coverage)",
			"errors", errors.Join(errs...))
	}

	return &linuxLSMHandle{
		objs:       &objs,
		links:      links,
		SockOwners: objs.SockOwners,
		logger:     logger,
	}, nil
}
