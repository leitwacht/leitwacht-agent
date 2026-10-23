//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"testing"
)

// TestProcessInfoEntrySize guards that the Go processInfoEntry struct
// round-trips the packed C struct process_info (256 + 8 + 8 + 8 = 280
// bytes) with no Go-compiler-injected padding. Any drift between the
// BPF C side and this Go struct silently corrupts binary_path decoding.
// binary.Size returns -1 if the struct contains a field with
// non-fixed-width type — that alone would catch most layout breakage.
func TestProcessInfoEntrySize(t *testing.T) {
	t.Parallel()

	const want = binaryPathLen + 8 + 8 + 8 // 256 + exec_ts + cgroup_id + exec_id = 280

	if got := binary.Size(processInfoEntry{}); got != want {
		t.Errorf("processInfoEntry layout drift: binary.Size = %d, want %d "+
			"(check that binaryPathLen stays a multiple of 8 or add "+
			"explicit padding to keep the struct aligned)", got, want)
	}
}

// TestDNSPIDAttrLayoutConstants guards the byte-offset constants used
// by Lookup to decode the BPF attribution map value. The total size
// must match struct dns_pid_attribution in dns_pid.c.
func TestDNSPIDAttrLayoutConstants(t *testing.T) {
	t.Parallel()

	// 4 (pid) + 16 (comm) + 16 (parent_comm) + 8 (cgroup_id) = 44.
	// Next fields are ts_ns(8) + flags(1), not read by Lookup.
	if attrOffsetComm != 4 ||
		attrOffsetParentComm != 20 ||
		attrOffsetCgroupID != 36 ||
		dnsPIDAttrSize != 53 {
		t.Fatalf("attribution offsets drift: "+
			"pid=%d comm=%d parent=%d cgroup=%d total=%d",
			attrOffsetPID, attrOffsetComm, attrOffsetParentComm,
			attrOffsetCgroupID, dnsPIDAttrSize)
	}
}

// TestIsLSMFallbackable covers the typed error inspection that
// replaced the fragile strings.Contains detector. Each case represents
// a known failure shape the fallback-or-propagate decision depends on.
func TestIsLSMFallbackable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ENOTSUP from syscall layer", syscall.ENOTSUP, true},
		{"EOPNOTSUPP from syscall layer", syscall.EOPNOTSUPP, true},
		{"wrapped ENOTSUP", fmt.Errorf("attach lsm: %w", syscall.ENOTSUP), true},
		{"unrelated syscall error", syscall.ENOMEM, false},
		{"arbitrary string error", errors.New("some other failure"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isLSMFallbackable(tt.err)
			if got != tt.want {
				t.Errorf("isLSMFallbackable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
