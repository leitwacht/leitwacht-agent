//go:build linux

package enforcer

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// TestLSMSingletonReusesHandle verifies that ensureLSMSingleton returns
// the same kernel-side bundle across repeated calls. Without singleton
// behaviour, every per-pod LoadEBPF would re-attach the LSM programs
// at lsm/socket_connect and lsm/socket_sendmsg — the kernel runs ALL
// attached programs on every host-wide socket syscall, so cost scales
// linearly with attach count. This test is the unit-level guarantee
// that we attach exactly once per process.
//
// Run: sudo -E go test ./agentcore/enforcer/ -run TestLSMSingleton -v -count=1.
func TestLSMSingletonReusesHandle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	ShutdownSentinelLSM()

	t.Cleanup(ShutdownSentinelLSM)

	first, err := ensureLSMSingleton(testLogger())
	if err != nil {
		t.Skip("eBPF/LSM not available on this host: ", err)
	}

	if first == nil {
		t.Fatal("ensureLSMSingleton returned (nil, nil)")
	}

	second, err := ensureLSMSingleton(testLogger())
	if err != nil {
		t.Fatalf("ensureLSMSingleton (second call): %v", err)
	}

	if first != second {
		t.Fatal("singleton invariant violated: ensureLSMSingleton returned different handles")
	}

	if first.SockOwners == nil {
		t.Fatal("singleton handle missing SockOwners map")
	}

	if len(first.links) == 0 {
		t.Fatal("singleton handle has no LSM links — degraded mode unexpected on a kernel that supports lsm/")
	}
}

// TestLSMSingletonEgressShare verifies that two independent LoadEBPF calls
// (the per-pod path) end up wired to the SAME sock_owners map instance —
// not two parallel allocations. We compare ebpf.MapInfo IDs because
// cilium/ebpf returns the same Go-side *ebpf.Map only when the FD is
// reused; the kernel-level identity is the MapInfo.ID.
func TestLSMSingletonEgressShare(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	ShutdownSentinelLSM()
	t.Cleanup(ShutdownSentinelLSM)

	platform := &LinuxPlatform{Logger: testLogger()}

	h1, err := platform.LoadEBPF(true, nil)
	if err != nil {
		t.Skip("LoadEBPF unavailable on this host: ", err)
	}
	defer h1.Close() //nolint:errcheck // test cleanup

	h2, err := platform.LoadEBPF(true, nil)
	if err != nil {
		t.Fatalf("second LoadEBPF: %v", err)
	}
	defer h2.Close() //nolint:errcheck // test cleanup

	lh1, ok1 := h1.(*linuxEBPFHandle)
	lh2, ok2 := h2.(*linuxEBPFHandle)

	if !ok1 || !ok2 {
		t.Fatalf("expected *linuxEBPFHandle, got %T / %T", h1, h2)
	}

	if lh1.lsm == nil || lh2.lsm == nil {
		t.Fatal("expected both handles to share singleton LSM, but at least one is in degraded mode")
	}

	if lh1.lsm != lh2.lsm {
		t.Fatal("two LoadEBPF calls produced different LSM handles — singleton broken")
	}

	id1 := mapID(t, lh1.lsm.SockOwners)
	id2 := mapID(t, lh2.lsm.SockOwners)

	if id1 != id2 {
		t.Fatalf("sock_owners map IDs differ: %d vs %d (LSM singleton not shared)", id1, id2)
	}
}

// TestLSMSingletonGateMapAndConnect verifies the userspace path that
// feeds the LSM hook's filter: AddSockKnownCgroup writes through to the
// kernel HASH map (Lookup confirms the value), and a real connect()
// from a registered cgroup runs without crashing the kernel or
// disturbing the singleton.
//
// We do not directly assert that sock_owners gained an entry. SK_STORAGE
// iteration via BPF_MAP_GET_NEXT_KEY is unsupported by the kernel by
// design — keys are kernel-internal socket pointers with no userspace
// meaning. Verifying actual capture requires either a SEC("iter/...")
// program or the indirect drop-event path; the latter is already
// covered end-to-end in TestIntegrationBinaryPathShortLivedExecs.
func TestLSMSingletonGateMapAndConnect(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	ShutdownSentinelLSM()
	t.Cleanup(ShutdownSentinelLSM)

	lsm, err := ensureLSMSingleton(testLogger())
	if err != nil {
		t.Skip("eBPF/LSM not available on this host: ", err)
	}

	myCgroupID := readMyCgroupID(t)

	err = lsm.AddSockKnownCgroup(myCgroupID)
	if err != nil {
		t.Fatalf("AddSockKnownCgroup: %v", err)
	}

	t.Cleanup(func() { lsm.RemoveSockKnownCgroup(myCgroupID) })

	var gateValue uint8

	gateErr := lsm.objs.SockKnownCgroups.Lookup(myCgroupID, &gateValue)
	if gateErr != nil {
		t.Fatalf("sock_known_cgroups lookup for cgroup_id=%d: %v", myCgroupID, gateErr)
	}

	if gateValue != 1 {
		t.Fatalf("sock_known_cgroups[%d] = %d, want 1", myCgroupID, gateValue)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	go func() {
		conn, accErr := ln.Accept()
		if accErr == nil {
			conn.Close() //nolint:errcheck // test cleanup
		}
	}()

	conn, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	conn.Close() //nolint:errcheck // test cleanup

	again, err := ensureLSMSingleton(testLogger())
	if err != nil {
		t.Fatalf("singleton re-resolve after connect: %v", err)
	}

	if again != lsm {
		t.Fatal("singleton handle changed across connect()")
	}
}

// TestLSMSingletonKernelDedup is the load-bearing kernel-truth proof.
// Without singleton-sharing, every LoadEBPF would issue link.AttachLSM
// twice (connect + sendmsg), creating two NEW lsm_mac links per call.
// We use bpftool -j to enumerate links and filter to those whose prog_id
// matches the freshly-loaded sock_attr programs, so the assertion is
// immune to (a) baseline lsm_mac links from other security tooling and
// (b) concurrent LSM attaches happening between snapshots.
func TestLSMSingletonKernelDedup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	_, lookupErr := exec.LookPath("bpftool")
	if lookupErr != nil {
		t.Skip("bpftool not available on this host")
	}

	ShutdownSentinelLSM()
	t.Cleanup(ShutdownSentinelLSM)

	platform := &LinuxPlatform{Logger: testLogger()}

	const loadCount = 5

	handles := loadEBPFNTimes(t, platform, loadCount)

	t.Cleanup(func() {
		for _, h := range handles {
			_ = h.Close()
		}
	})

	connectProgID := singleProgIDByName(t, "sock_attr_connect")
	sendmsgProgID := singleProgIDByName(t, "sock_attr_sendmsg")

	links := lsmLinksByProgID(t, map[int]bool{
		connectProgID: true,
		sendmsgProgID: true,
	})

	// The singleton-correct outcome: exactly one lsm_mac link per
	// program, regardless of how many LoadEBPF calls preceded.
	if len(links) != 2 {
		dumpLSMLinks(t)
		t.Fatalf("expected exactly 2 lsm_mac links pointing at our sock_attr "+
			"programs (one connect, one sendmsg) after %d LoadEBPF calls; "+
			"got %d (link IDs %v) — kernel-level LSM dedup is broken",
			loadCount, len(links), links)
	}

	t.Logf("after %d LoadEBPF calls: 2 lsm_mac links (IDs %v) for prog_ids %d & %d",
		loadCount, links, connectProgID, sendmsgProgID)
}

// TestLSMSingletonDegradedMode forces ensureLSMSingleton to fail and
// asserts that LoadEBPF still produces a working egress collection. The
// degraded path is the production fallback when bpf-lsm isn't enabled
// (e.g. a kernel without lsm=bpf in cmdline). Without this test, we'd
// only catch a regression on a kernel that genuinely lacks LSM support
// — and the integration host has it, so the path would never run.
func TestLSMSingletonDegradedMode(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	if _, err := ensureLSMSingleton(testLogger()); err != nil {
		t.Skip("eBPF unavailable on this host: ", err)
	}
	ShutdownSentinelLSM()
	t.Cleanup(ShutdownSentinelLSM)

	prev := lsmBundleLoader

	t.Cleanup(func() { lsmBundleLoader = prev })

	forcedErr := errors.New("forced singleton failure for test")
	lsmBundleLoader = func(_ *slog.Logger) (*linuxLSMHandle, error) {
		return nil, forcedErr
	}

	// Sanity: the singleton must propagate the forced failure verbatim.
	_, err := ensureLSMSingleton(testLogger())
	if !errors.Is(err, forcedErr) {
		t.Fatalf("expected forced error, got %v", err)
	}

	// Production behaviour: LoadEBPF must still succeed in degraded
	// mode (Warn-log and proceed without sk_storage attribution).
	platform := &LinuxPlatform{Logger: testLogger()}

	h, err := platform.LoadEBPF(true, nil)
	if err != nil {
		t.Fatalf("LoadEBPF in degraded mode: %v", err)
	}
	defer h.Close() //nolint:errcheck // test cleanup

	lh, ok := h.(*linuxEBPFHandle)
	if !ok {
		t.Fatalf("expected *linuxEBPFHandle, got %T", h)
	}

	if lh.lsm != nil {
		t.Fatal("expected lsm == nil in degraded mode, got non-nil singleton")
	}

	// Sock-known-cgroup writes must no-op cleanly (not panic, not error).
	addErr := h.AddSockKnownCgroup(99999)
	if addErr != nil {
		t.Errorf("AddSockKnownCgroup in degraded mode returned error: %v", addErr)
	}

	h.RemoveSockKnownCgroup(99999) // returns void; just must not panic
}

// TestLSMSingletonShutdownReload verifies that ShutdownSentinelLSM
// produces a clean slate: a subsequent ensureLSMSingleton call yields
// a fresh handle with a NEW kernel sock_owners map ID, not a stale
// reference to the closed bundle.
func TestLSMSingletonShutdownReload(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	ShutdownSentinelLSM()
	t.Cleanup(ShutdownSentinelLSM)

	first, err := ensureLSMSingleton(testLogger())
	if err != nil {
		t.Skip("eBPF/LSM not available on this host: ", err)
	}

	firstID := mapID(t, first.SockOwners)

	ShutdownSentinelLSM()

	second, err := ensureLSMSingleton(testLogger())
	if err != nil {
		t.Fatalf("ensureLSMSingleton after shutdown: %v", err)
	}

	if first == second {
		t.Fatal("expected fresh handle after ShutdownSentinelLSM, got cached one")
	}

	secondID := mapID(t, second.SockOwners)

	if firstID == secondID {
		t.Fatalf("expected fresh sock_owners map after shutdown; got same ID %d twice "+
			"(ShutdownSentinelLSM did not actually release the map)", firstID)
	}

	t.Logf("shutdown-reload produced fresh map ID: %d → %d", firstID, secondID)
}

// --- helpers -------------------------------------------------------------

func mapID(t *testing.T, m *ebpf.Map) ebpf.MapID {
	t.Helper()

	info, err := m.Info()
	if err != nil {
		t.Fatalf("map info: %v", err)
	}

	id, ok := info.ID()
	if !ok {
		t.Fatal("MapInfo.ID() unavailable; cannot verify shared kernel identity")
	}

	return id
}

// readMyCgroupID returns the cgroup inode of the test process. Equivalent
// to bpf_get_current_cgroup_id() that the LSM hook will see.
func readMyCgroupID(t *testing.T) uint64 {
	t.Helper()

	myCgroupPath, err := getCgroupPath(os.Getpid())
	if err != nil {
		t.Fatalf("get test process cgroup: %v", err)
	}

	var st syscall.Stat_t

	statErr := syscall.Stat(myCgroupPath, &st)
	if statErr != nil {
		t.Fatalf("stat cgroup %q: %v", myCgroupPath, statErr)
	}

	return st.Ino
}

// loadEBPFNTimes wraps the boilerplate of producing N independent egress
// handles (the test-shape of "N pods attaching back-to-back").
func loadEBPFNTimes(t *testing.T, platform *LinuxPlatform, n int) []EBPFHandle {
	t.Helper()

	handles := make([]EBPFHandle, 0, n)

	for i := range n {
		h, err := platform.LoadEBPF(true, nil)
		if err != nil {
			if i == 0 {
				t.Skip("LoadEBPF unavailable on this host: ", err)
			}

			t.Fatalf("LoadEBPF iteration %d: %v", i, err)
		}

		handles = append(handles, h)
	}

	return handles
}

// bpftoolLink and bpftoolProg model the JSON shape of `bpftool ... -j`
// for the fields we need. Fields we don't reference are ignored, so
// future bpftool changes that add fields don't break the test.
//
// Note on Type vs AttachType: bpftool reports the *kind* of link in
// "type" (e.g. "tracing", "perf_event", "iter"). For tracing links,
// the actual hook discriminator is in "attach_type" — that's where
// "lsm_mac" appears for LSM hooks. Filter on attach_type, not type.
type bpftoolLink struct {
	ID         int    `json:"id"`
	Type       string `json:"type"`
	AttachType string `json:"attach_type"`
	ProgID     int    `json:"prog_id"`
}

type bpftoolProg struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// decodeBpftoolJSONArray normalises bpftool -j output and decodes it
// into dst (which must be a *[]T). Necessary because bpftool returns a
// bare JSON object for single-result queries (e.g. `prog show name X`
// when exactly one match exists) and a JSON array for multi-result
// queries (e.g. `link show`). Empty output also becomes "[]".
func decodeBpftoolJSONArray(raw []byte, dst any) error {
	raw = bytes.TrimSpace(raw)

	switch {
	case len(raw) == 0:
		raw = []byte("[]")
	case raw[0] == '{':
		// Single object — wrap so json.Unmarshal can decode into a slice.
		wrapped := make([]byte, 0, len(raw)+2)
		wrapped = append(wrapped, '[')
		wrapped = append(wrapped, raw...)
		wrapped = append(wrapped, ']')
		raw = wrapped
	}

	return json.Unmarshal(raw, dst)
}

// lsmLinksByProgID returns the bpf_link IDs whose attached program ID
// is in want. Robust to baseline lsm_mac links from other tooling and
// to concurrent LSM attaches happening during the test.
func lsmLinksByProgID(t *testing.T, want map[int]bool) []int {
	t.Helper()

	out, err := exec.Command("bpftool", "-j", "link", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("bpftool -j link show: %v: %s", err, out)
	}

	var links []bpftoolLink

	jsonErr := decodeBpftoolJSONArray(out, &links)
	if jsonErr != nil {
		t.Fatalf("decode bpftool link json: %v: %s", jsonErr, out)
	}

	matches := make([]int, 0, len(want))

	for _, l := range links {
		if l.AttachType != "lsm_mac" {
			continue
		}

		if want[l.ProgID] {
			matches = append(matches, l.ID)
		}
	}

	return matches
}

// singleProgIDByName resolves the kernel program ID for the unique
// loaded program named name. Fails the test if there is anything other
// than exactly one such program (zero = never loaded; >1 = load-time
// dedup broken).
func singleProgIDByName(t *testing.T, name string) int {
	t.Helper()

	out, err := exec.Command("bpftool", "-j", "prog", "show", "name", name).CombinedOutput()
	if err != nil {
		t.Fatalf("bpftool -j prog show name %s: %v: %s", name, err, out)
	}

	var progs []bpftoolProg

	jsonErr := decodeBpftoolJSONArray(out, &progs)
	if jsonErr != nil {
		t.Fatalf("decode bpftool prog json: %v: %s", jsonErr, out)
	}

	if len(progs) != 1 {
		t.Fatalf("expected exactly 1 loaded %s program, got %d (load-time dedup broken)",
			name, len(progs))
	}

	return progs[0].ID
}

// dumpLSMLinks logs the full bpftool link show output. Called only on
// failure paths to make diagnosis trivial.
func dumpLSMLinks(t *testing.T) {
	t.Helper()

	out, _ := exec.Command("bpftool", "link", "show").CombinedOutput()
	t.Logf("bpftool link show (full):\n%s", string(out))
}
