//go:build linux

package enforcer

import "github.com/cilium/ebpf"

// readReserveFailures sums a per-CPU reserve_failures counter (a
// single-entry PERCPU_ARRAY of u64). A nil map or read error yields 0.
func readReserveFailures(m *ebpf.Map) uint64 {
	if m == nil {
		return 0
	}

	var perCPU []uint64

	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}

	var total uint64

	for _, v := range perCPU {
		total += v
	}

	return total
}

// ReserveFailures returns the number of egress drop events lost because
// the drop ring buffer was full (summed across CPUs). The drop verdict
// is unaffected; only the evidence is lost.
func (h *linuxEBPFHandle) ReserveFailures() uint64 {
	return readReserveFailures(h.objs.ReserveFailures)
}
