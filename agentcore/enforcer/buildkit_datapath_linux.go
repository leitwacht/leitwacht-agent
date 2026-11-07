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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// bkCgValSize is sizeof(struct bk_cg_val) in egress_bk.h.
const bkCgValSize = 16

// LoadBuildKitEBPF loads the egress_bk object (slot-table datapath for
// BuildKit RUN cgroups). It shares the sock_attr LSM singleton with the
// per-pod object so socket attribution is the same.
func (p *LinuxPlatform) LoadBuildKitEBPF(trustedCIDRs []net.IPNet) (BuildKitDatapath, error) {
	lsm, lsmErr := ensureLSMSingleton(p.Logger)
	if lsmErr != nil {
		p.Logger.Warn("sock_attr LSM singleton unavailable; buildkit packet attribution unavailable",
			"error", lsmErr)
	}

	spec, err := loadEbpfBK()
	if err != nil {
		return nil, fmt.Errorf("load egress_bk spec: %w", err)
	}

	for name, want := range map[string]uint32{
		"drop_event": minBKDropEventSize,
		"sock_owner": sockOwnerSize,
		"bk_cg_val":  bkCgValSize,
	} {
		if verr := verifyStructSize(spec.Types, name, want); verr != nil {
			return nil, fmt.Errorf("egress_bk bytecode verify: %w", verr)
		}
	}

	var collOpts *ebpf.CollectionOptions
	if lsm != nil {
		collOpts = &ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{"sock_owners": lsm.SockOwners},
		}
	}

	h := &linuxBKHandle{logger: p.Logger, lsm: lsm}

	// The inner-map templates: slots are created from these specs.
	for name, dst := range map[string]**ebpf.MapSpec{
		"bk_deny_sets": &h.denyInner,
		"bk_host_sets": &h.hostInner,
		"bk_dns_sets":  &h.dnsInner,
	} {
		ms := spec.Maps[name]
		if ms == nil || ms.InnerMap == nil {
			return nil, fmt.Errorf("egress_bk: map %s has no inner map template", name) //nolint:err113 // load-time invariant
		}

		*dst = ms.InnerMap.Copy()
	}

	err = spec.LoadAndAssign(&h.objs, collOpts)
	if err != nil {
		return nil, fmt.Errorf("load egress_bk objects: %w", err)
	}

	for _, cidr := range trustedCIDRs {
		ones, _ := cidr.Mask.Size()

		ip4 := cidr.IP.To4()
		if ip4 == nil {
			continue
		}

		key := packLPMKey(ip4, ones)

		if putErr := h.objs.TrustedNets.Put(key[:], uint8(1)); putErr != nil {
			p.Logger.Error("put trusted_nets (buildkit)", "cidr", cidr.String(), "error", putErr)
		}
	}

	return h, nil
}

// linuxBKHandle is the loaded egress_bk object.
type linuxBKHandle struct {
	objs   ebpfBKObjects
	logger *slog.Logger
	lsm    *linuxLSMHandle

	denyInner, hostInner, dnsInner *ebpf.MapSpec

	mu sync.Mutex // serialises slot installs/removals
}

// AttachCgroup attaches the egress program at cgroupPath.
func (h *linuxBKHandle) AttachCgroup(cgroupPath string) (CgroupLink, error) {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: h.objs.EgressFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("attach egress_bk cgroup: %w", err)
	}

	return &linuxCgroupLink{link: l}, nil
}

// SetConfig writes bk_cfg.
func (h *linuxBKHandle) SetConfig(c BKConfig) error {
	if len(c.ParentIDs) > bkMaxParents || len(c.DNSUpstreams) > bkMaxDNS {
		return fmt.Errorf("%w: %d parents, %d dns upstreams", errBKConfigRange, len(c.ParentIDs), len(c.DNSUpstreams))
	}

	v := ebpfBKBkCfgVal{RunLevel: c.RunLevel, N_parents: uint32(len(c.ParentIDs)), N_dns: uint32(len(c.DNSUpstreams))} //nolint:gosec // bounded above

	copy(v.Parents[:], c.ParentIDs)

	for i, ip := range c.DNSUpstreams {
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("%w: %s is not IPv4", errBKConfigRange, ip)
		}

		// Network byte order, as iph.daddr is read.
		v.DnsIp[i] = binary.LittleEndian.Uint32(ip4)
	}

	if err := h.objs.BkCfg.Put(uint32(0), &v); err != nil {
		return fmt.Errorf("set bk_cfg: %w", err)
	}

	return nil
}

// InstallSlot builds the slot's three inner maps and publishes them.
// Nothing is published unless every entry fit.
func (h *linuxBKHandle) InstallSlot(slot uint32, rules BKSlotRules) error {
	if slot >= bkMaxSlots {
		return fmt.Errorf("%w: slot %d", errBKSlotRange, slot)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	deny, err := ebpf.NewMap(h.denyInner)
	if err != nil {
		return fmt.Errorf("create deny map: %w", err)
	}

	defer deny.Close() //nolint:errcheck // the kernel keeps its own reference once published

	host, err := ebpf.NewMap(h.hostInner)
	if err != nil {
		return fmt.Errorf("create host map: %w", err)
	}

	defer host.Close() //nolint:errcheck // as above

	dns, err := ebpf.NewMap(h.dnsInner)
	if err != nil {
		return fmt.Errorf("create dns map: %w", err)
	}

	defer dns.Close() //nolint:errcheck // as above

	err = fillRuleMap(deny, rules.Deny)
	if err != nil {
		return fmt.Errorf("fill deny map: %w", err)
	}

	err = fillRuleMap(host, rules.Allow)
	if err != nil {
		return fmt.Errorf("fill host map: %w", err)
	}

	// Publish. If the slot was published before (an in-place reinstall),
	// the three Puts replace the maps one by one; the binder never
	// reinstalls a live slot, it builds a new one and flips cgroups.
	for _, e := range []struct {
		outer *ebpf.Map
		inner *ebpf.Map
		name  string
	}{
		{h.objs.BkDenySets, deny, "deny"},
		{h.objs.BkHostSets, host, "host"},
		{h.objs.BkDnsSets, dns, "dns"},
	} {
		if putErr := e.outer.Put(slot, e.inner); putErr != nil {
			// Roll back what was published so the slot is never half in.
			_ = h.objs.BkDenySets.Delete(slot)
			_ = h.objs.BkHostSets.Delete(slot)
			_ = h.objs.BkDnsSets.Delete(slot)

			return fmt.Errorf("publish %s map: %w", e.name, putErr)
		}
	}

	return nil
}

var (
	errBKSlotRange   = errors.New("buildkit slot out of range")
	errBKConfigRange = errors.New("buildkit config out of range")
)

// fillRuleMap writes rules; first writer of a key wins (lowest prio
// first), matching collectIPRules' per-key dedup.
func fillRuleMap(m *ebpf.Map, rules []BuildIPRule) error {
	for _, r := range rules {
		ip := net.ParseIP(r.IP)
		if ip == nil || ip.To4() == nil {
			continue
		}

		key := PackAllowKey(ip, r.Port)

		var existing uint32
		if err := m.Lookup(key[:], &existing); err == nil && existing <= r.Prio {
			continue
		}

		if err := m.Put(key[:], r.Prio); err != nil {
			return fmt.Errorf("put %s:%d: %w", r.IP, r.Port, err)
		}
	}

	return nil
}

// RemoveSlot unpublishes a slot (idempotent).
func (h *linuxBKHandle) RemoveSlot(slot uint32) error {
	if slot >= bkMaxSlots {
		return fmt.Errorf("%w: slot %d", errBKSlotRange, slot)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var first error

	for _, m := range []*ebpf.Map{h.objs.BkDenySets, h.objs.BkHostSets, h.objs.BkDnsSets} {
		if err := m.Delete(slot); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && first == nil {
			first = err
		}
	}

	if first != nil {
		return fmt.Errorf("remove slot %d: %w", slot, first)
	}

	return nil
}

// SetCgroupPolicy writes a cgroup's entry.
func (h *linuxBKHandle) SetCgroupPolicy(cgroupID uint64, p BKCgroupPolicy) error {
	v := ebpfBKBkCgVal{Slot: p.Slot, State: p.State, Mode: p.Mode, Gen: p.Gen}

	// BPF_F_LOCK: the program reads the tuple under the same spin lock,
	// so an in-place replace is never seen half-written.
	if err := h.objs.BkCgroupPolicy.Update(cgroupID, &v, ebpf.UpdateAny|ebpf.UpdateLock); err != nil {
		return fmt.Errorf("put bk_cgroup_policy: %w", err)
	}

	return nil
}

// DeleteCgroupPolicy removes a cgroup's entry.
func (h *linuxBKHandle) DeleteCgroupPolicy(cgroupID uint64) error {
	if err := h.objs.BkCgroupPolicy.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete bk_cgroup_policy: %w", err)
	}

	return nil
}

// ReserveFailures reports lost events (ring full).
func (h *linuxBKHandle) ReserveFailures() uint64 {
	return readReserveFailures(h.objs.ReserveFailures)
}

// StartRingbufReader reads egress_bk events. Each event carries its
// verdict, so the action never depends on a global mode.
func (h *linuxBKHandle) StartRingbufReader(
	ctx context.Context,
	lookupRecorder func(cgroupID uint64) *ViolationRecorder,
) (func(), error) {
	reader, err := ringbuf.NewReader(h.objs.DropEvents)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)

	wg.Go(func() {
		<-ctx.Done()
		reader.Close() //nolint:errcheck,gosec // cleanup
	})

	wg.Go(func() {
		monitorReserveFailures(ctx.Done(), "egress_bk_drop", h.ReserveFailures, h.logger, reserveFailureInterval)
	})

	wg.Go(func() {
		for {
			record, rerr := reader.Read()
			if rerr != nil {
				if errors.Is(rerr, ringbuf.ErrClosed) {
					return
				}

				h.logger.Debug("ringbuf read error", "error", rerr)

				continue
			}

			v, state, ok := decodeBKEvent(record.RawSample, time.Now())
			if !ok {
				continue
			}

			recorder := lookupRecorder(v.CgroupID)
			if recorder == nil {
				continue
			}

			if binding, found := LookupBuildKitBinding(v.CgroupID); found {
				applyBuildKitBinding(&v, binding)
			}

			noteBKEventState(v.CgroupID, state)

			recorder.RecordViolation(v)
		}
	})

	return func() {
		cancel()
		wg.Wait()
	}, nil
}

// Close releases the object. The LSM singleton is not owned here.
func (h *linuxBKHandle) Close() error {
	return h.objs.Close()
}

// AddSockKnownAncestor registers a subtree root with the LSM filter.
func (h *linuxBKHandle) AddSockKnownAncestor(cgroupID uint64) error {
	if h.lsm == nil {
		return nil
	}

	return h.lsm.AddSockKnownAncestor(cgroupID)
}

// RemoveSockKnownAncestor drops one reference to a subtree root.
func (h *linuxBKHandle) RemoveSockKnownAncestor(cgroupID uint64) {
	if h.lsm == nil {
		return
	}

	h.lsm.RemoveSockKnownAncestor(cgroupID)
}
