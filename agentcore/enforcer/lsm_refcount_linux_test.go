//go:build linux

package enforcer

import "testing"

// TestRefSet covers the reference counting behind the shared
// sock_known_* maps: an old attach closing after its replacement
// started (resolver swap) must not delete the entry the new one holds.
func TestRefSet(t *testing.T) {
	t.Parallel()

	var r refSet

	if !r.acquire(7) {
		t.Fatal("first acquire not reported first")
	}

	if r.acquire(7) {
		t.Fatal("second acquire reported first")
	}

	if r.release(7) {
		t.Fatal("release with a reference left reported last")
	}

	if !r.release(7) {
		t.Fatal("final release not reported last")
	}

	if r.release(7) {
		t.Fatal("release of an unheld id reported last")
	}
}

// TestLSMHandleRefcountsSharedIDs drives linuxLSMHandle-independent
// refcount through both registration kinds with a nil-map handle.
func TestLSMHandleRefcountsSharedIDs(t *testing.T) {
	t.Parallel()

	h := &linuxLSMHandle{}

	_ = h.AddSockKnownAncestor(9)
	_ = h.AddSockKnownAncestor(9)
	h.RemoveSockKnownAncestor(9)

	if got := h.ancestorRefs.counts[9]; got != 1 {
		t.Errorf("ancestor refs = %d after add,add,remove; want 1", got)
	}

	_ = h.AddSockKnownCgroup(5)
	_ = h.AddSockKnownCgroup(5)
	h.RemoveSockKnownCgroup(5)

	if got := h.cgroupRefs.counts[5]; got != 1 {
		t.Errorf("cgroup refs = %d after add,add,remove; want 1", got)
	}
}
