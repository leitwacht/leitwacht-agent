//go:build linux

package enforcer

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// Static error sentinels so callers (and tests) can match with errors.Is.
// The dynamic context (struct name, actual size, expected size) is added
// via fmt.Errorf("...%w", Err*) wrapping in verifyStructSize.
var (
	// ErrBTFStructNotFound means the named struct isn't present in the
	// bytecode's BTF — typically because clang dropped it as unused.
	// Fix is to add a forced-used reference in the .c source.
	ErrBTFStructNotFound = errors.New("struct not present in bytecode BTF")

	// ErrBTFStructSizeMismatch means the bytecode's BTF-reported size for
	// a struct differs from the size the userspace decoder assumes. Fix
	// is to regenerate bytecode (go generate ./agentcore/enforcer/).
	ErrBTFStructSizeMismatch = errors.New("struct layout mismatch between bytecode and userspace")
)

// verifyStructSize asserts that a struct in the embedded BPF bytecode's BTF
// matches the size the userspace decoder assumes. A mismatch means the .c
// source was modified without rerunning go generate (or vice versa), so the
// byte-offset decodes in Go will read garbage.
//
// Called at agent startup; refusing to load is preferable to the silent
// failure mode that shipped in agent 1.63.x/1.69.x: egress.c's drop_event
// grew 16→36 bytes, userspace's minDropEventSize was bumped to 36, but the
// committed .o still emitted 16-byte events. Every ringbuf sample failed the
// `len(RawSample) < minDropEventSize` guard and got skipped with no log, no
// metric — packet_observed/packet_dropped/sinkhole_hit disappeared from
// production for two agent releases before anyone noticed.
func verifyStructSize(types *btf.Spec, name string, want uint32) error {
	var s *btf.Struct

	err := types.TypeByName(name, &s)
	if err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return fmt.Errorf("%s %q: %w — ensure the .c source declares "+
				"and references it, and that bpf2go emits BTF debug info",
				"lookup", name, ErrBTFStructNotFound)
		}

		return fmt.Errorf("lookup %q in BTF: %w", name, err)
	}

	if s.Size != want {
		return fmt.Errorf("%w: struct %q bytecode=%d bytes userspace=%d — "+
			"regenerate eBPF bytecode (go generate ./agentcore/enforcer/) "+
			"and rebuild the agent",
			ErrBTFStructSizeMismatch, name, s.Size, want)
	}

	return nil
}
