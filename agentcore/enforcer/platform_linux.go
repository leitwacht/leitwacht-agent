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
	"github.com/vishvananda/netns"
)

var errNotUDPConn = errors.New("dial returned non-UDP conn")

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

// NewUpstreamDialer opens the netns of pid. See Platform.NewUpstreamDialer.
func (p *LinuxPlatform) NewUpstreamDialer(pid int) (UpstreamDialer, error) {
	h, err := netns.GetFromPid(pid)
	if err != nil {
		return nil, fmt.Errorf("get netns for pid %d: %w", pid, err)
	}

	return &netnsDialer{handle: h}, nil
}

// netnsDialer dials from inside a held netns handle.
type netnsDialer struct {
	handle netns.NsHandle
}

func (d *netnsDialer) Close() error { return d.handle.Close() }

func markControl(mark int) func(_, _ string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
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
	}
}

func (d *netnsDialer) dial(network, addr string, mark int) (net.Conn, error) {
	var conn net.Conn

	err := inNetnsHandle(d.handle, func() error {
		dl := net.Dialer{Timeout: upstreamTimeout, Control: markControl(mark)}

		nc, dialErr := dl.DialContext(context.Background(), network, addr)
		if dialErr != nil {
			return fmt.Errorf("dial marked %s: %w", network, dialErr)
		}

		conn = nc

		return nil
	})
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}

		return nil, err
	}

	return conn, nil
}

func (d *netnsDialer) DialUDP(addr string, mark int) (*net.UDPConn, error) {
	nc, err := d.dial("udp4", addr, mark)
	if err != nil {
		return nil, err
	}

	uc, ok := nc.(*net.UDPConn)
	if !ok {
		_ = nc.Close()

		return nil, errNotUDPConn
	}

	return uc, nil
}

func (d *netnsDialer) DialTCP(addr string, mark int) (net.Conn, error) {
	return d.dial("tcp4", addr, mark)
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

	// Populate trusted CIDRs LPM trie. Count only entries that actually
	// landed: the map is bounded (trusted_nets max_entries), and a CIDR
	// that does not fit is an allow that silently never takes effect.
	cidrPuts := 0
	cidrFailed := 0
	trustedCap := int(objs.TrustedNets.MaxEntries())

	for _, cidr := range trustedCIDRs {
		ones, _ := cidr.Mask.Size()
		ip4 := cidr.IP.To4()

		if ip4 == nil {
			continue // skip IPv6 CIDRs
		}

		key := packLPMKey(ip4, ones)

		putErr := objs.TrustedNets.Put(key[:], uint8(1))
		if putErr != nil {
			cidrFailed++

			p.Logger.Error("put trusted_nets", "cidr", cidr.String(), "error", putErr, "capacity", trustedCap)

			continue
		}

		cidrPuts++
	}

	if cidrFailed > 0 {
		p.Logger.Error("trusted CIDRs not loaded; traffic to them will be dropped",
			"loaded", cidrPuts, "failed", cidrFailed, "capacity", trustedCap)
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

	// allowMu serialises AddAllowedIP's lookup-then-put so two resolutions
	// of one address cannot interleave and lose the better priority.
	allowMu sync.Mutex
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

// AddAllowedIP records a DNS-derived allow. prio is the priority of the
// fqdn rule that authorised the resolution. Several names can resolve to
// one address (shared CDN fronts), and the map holds one value per key:
// a blind overwrite made the result depend on query order, so a later
// lower-ranked rule could displace the better one. Keep the better
// (lower) of the existing and new priority instead.
func (h *linuxEBPFHandle) AddAllowedIP(ip net.IP, ports []int, prio uint32) error {
	h.allowMu.Lock()
	defer h.allowMu.Unlock()

	for _, port := range ports {
		key := PackAllowKey(ip, port)

		var existing uint32

		lookupErr := h.objs.AllowedIps.Lookup(key[:], &existing)
		if lookupErr == nil && existing < prio {
			continue
		}

		putErr := h.objs.AllowedIps.Put(key[:], prio)
		if putErr != nil {
			h.logger.Error("put allow map", "ip", ip, "port", port, "error", putErr)

			return fmt.Errorf("put allow map: %w", putErr)
		}
	}

	return nil
}

// AddAllowedHost writes to the non-LRU static allow map. A full map is
// reported rather than swallowed: silently dropping the entry would
// present as an intermittent connection failure in the workload, which
// is precisely the failure mode the non-LRU map exists to prevent.
func (h *linuxEBPFHandle) AddAllowedHost(ip net.IP, port int, prio uint32) error {
	key := PackAllowKey(ip, port)

	putErr := h.objs.AllowedHosts.Put(key[:], prio)
	if putErr != nil {
		h.logger.Error("put static allow map", "ip", ip, "port", port, "error", putErr)

		return fmt.Errorf("put static allow map: %w", putErr)
	}

	return nil
}

func (h *linuxEBPFHandle) RemoveAllowedHost(ip net.IP, port int) error {
	key := PackAllowKey(ip, port)

	delErr := h.objs.AllowedHosts.Delete(key[:])
	if delErr != nil && !errors.Is(delErr, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete static allow map: %w", delErr)
	}

	return nil
}

// FlushAllowedIPs deletes every DNS-derived allow entry. Iterating and
// deleting is safe here: the map is LRU and the kernel tolerates
// deletion during iteration, and any entry a live query re-seeds after
// the flush is by definition current.
func (h *linuxEBPFHandle) FlushAllowedIPs() error {
	var (
		key  [6]byte
		prio uint32
	)

	iter := h.objs.AllowedIps.Iterate()
	keys := make([][6]byte, 0, 64)

	for iter.Next(&key, &prio) {
		keys = append(keys, key)
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate allow map: %w", err)
	}

	for i := range keys {
		delErr := h.objs.AllowedIps.Delete(keys[i][:])
		if delErr != nil && !errors.Is(delErr, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete allow map entry: %w", delErr)
		}
	}

	return nil
}

func (h *linuxEBPFHandle) AddDeniedIP(ip net.IP, port int, prio uint32) error {
	key := PackAllowKey(ip, port)

	putErr := h.objs.DeniedIps.Put(key[:], prio)
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

	wg.Go(func() {
		monitorReserveFailures(ctx.Done(), "egress_drop", h.ReserveFailures, h.logger, reserveFailureInterval)
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

				// Per-row CI override: the CI runner passes CI metadata
				// as --build-arg LEITWACHT_CI_*= when invoking docker
				// buildx. BuildKit propagates these as FrontendAttrs on
				// the session; the cgroup-join layer carries them
				// through to the binding. For a persistent shared
				// buildkitd that serves many CI jobs, this is how each
				// violation row attributes to the real job rather than
				// to the buildkitd pod's own labels.
				v.BuildProjectPath, v.BuildJobID, v.BuildPipelineID,
					v.BuildJobName, v.BuildJobStage, v.BuildGitRef,
					v.BuildJobURL = CIOverrideFromFrontendAttrs(binding.FrontendAttrs)
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

// AddSockKnownAncestor registers a cgroup whose whole subtree is
// monitored by the sock_attr filter (see sock_known_ancestors).
func (h *linuxEBPFHandle) AddSockKnownAncestor(cgroupID uint64) error {
	if h.lsm == nil {
		return nil
	}

	return h.lsm.AddSockKnownAncestor(cgroupID)
}

// RemoveSockKnownAncestor drops one reference to a subtree root.
func (h *linuxEBPFHandle) RemoveSockKnownAncestor(cgroupID uint64) {
	if h.lsm == nil {
		return
	}

	h.lsm.RemoveSockKnownAncestor(cgroupID)
}

// refSet counts registrations per cgroup id. The sock_known_* maps are
// process-wide and shared by every attach, so two owners registering the
// same id (an old and a new BuildKit attach during a resolver swap, or
// overlapping per-pod registrations) must not delete each other's entry:
// the map entry exists while at least one reference does.
type refSet struct {
	mu     sync.Mutex
	counts map[uint64]int
}

// distinct returns the number of ids with at least one reference.
func (r *refSet) distinct() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.counts)
}

// acquire adds a reference and reports whether it is the first.
func (r *refSet) acquire(id uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.counts == nil {
		r.counts = make(map[uint64]int)
	}

	r.counts[id]++

	return r.counts[id] == 1
}

// release drops a reference and reports whether it was the last. A
// release with no reference is a no-op (idempotent callers).
func (r *refSet) release(id uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, ok := r.counts[id]
	if !ok {
		return false
	}

	if n <= 1 {
		delete(r.counts, id)

		return true
	}

	r.counts[id] = n - 1

	return false
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

	cgroupRefs   refSet // sock_known_cgroups registrations
	ancestorRefs refSet // sock_known_ancestors registrations

	// flagMu serializes updates of the sock_ancestors_active flag so the
	// last remover and a concurrent first adder cannot interleave.
	flagMu sync.Mutex
}

// syncAncestorFlag publishes whether any subtree root is registered, so
// the BPF side can skip the ancestor probe entirely when none is.
func (h *linuxLSMHandle) syncAncestorFlag() {
	if h.objs == nil || h.objs.SockAncestorsActive == nil {
		return
	}

	h.flagMu.Lock()
	defer h.flagMu.Unlock()

	var v uint8
	if h.ancestorRefs.distinct() > 0 {
		v = 1
	}

	_ = h.objs.SockAncestorsActive.Put(uint32(0), v)
}

// AddSockKnownCgroup registers a cgroup_id with the LSM filter
// (reference counted). Returns nil if the SockKnownCgroups map is
// unavailable (defensive — shouldn't happen once the singleton is
// loaded).
func (h *linuxLSMHandle) AddSockKnownCgroup(cgroupID uint64) error {
	first := h.cgroupRefs.acquire(cgroupID)

	if !first || h.objs == nil || h.objs.SockKnownCgroups == nil {
		return nil
	}

	err := h.objs.SockKnownCgroups.Put(cgroupID, uint8(1))
	if err != nil {
		h.cgroupRefs.release(cgroupID)

		return fmt.Errorf("put sock_known_cgroups: %w", err)
	}

	return nil
}

// RemoveSockKnownCgroup drops one reference to a cgroup_id and deletes
// the map entry with the last one. Idempotent.
func (h *linuxLSMHandle) RemoveSockKnownCgroup(cgroupID uint64) {
	if !h.cgroupRefs.release(cgroupID) || h.objs == nil || h.objs.SockKnownCgroups == nil {
		return
	}

	_ = h.objs.SockKnownCgroups.Delete(cgroupID)
}

// AddSockKnownAncestor registers a subtree root (reference counted).
func (h *linuxLSMHandle) AddSockKnownAncestor(cgroupID uint64) error {
	first := h.ancestorRefs.acquire(cgroupID)

	if !first || h.objs == nil || h.objs.SockKnownAncestors == nil {
		return nil
	}

	err := h.objs.SockKnownAncestors.Put(cgroupID, uint8(1))
	if err != nil {
		h.ancestorRefs.release(cgroupID)

		return fmt.Errorf("put sock_known_ancestors: %w", err)
	}

	h.syncAncestorFlag()

	return nil
}

// RemoveSockKnownAncestor drops one reference to a subtree root.
func (h *linuxLSMHandle) RemoveSockKnownAncestor(cgroupID uint64) {
	if !h.ancestorRefs.release(cgroupID) || h.objs == nil || h.objs.SockKnownAncestors == nil {
		return
	}

	_ = h.objs.SockKnownAncestors.Delete(cgroupID)

	h.syncAncestorFlag()
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
