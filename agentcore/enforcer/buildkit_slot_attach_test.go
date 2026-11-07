package enforcer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeBKPlatform is a Platform that can also load the egress_bk object.
type fakeBKPlatform struct {
	*fakePlatform
	dp      *fakeDP
	trusted []net.IPNet
}

func (f *fakeBKPlatform) LoadBuildKitEBPF(trusted []net.IPNet) (BuildKitDatapath, error) {
	f.trusted = trusted

	return f.dp, nil
}

func TestSlotAttach_BindsFlushesAndAnnotates(t *testing.T) {
	t.Parallel()

	plat := &fakeBKPlatform{fakePlatform: &fakePlatform{}, dp: newFakeDP()}
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)

	src := newFakeSource()
	src.set("g/a", "build", enforcePol(1, "1.1.1.1"))

	var (
		mu       sync.Mutex
		reported []Violation
	)

	report := func(_ context.Context, _ ContainerInfo, stats *EgressStats, _ bool, _ time.Time) {
		mu.Lock()
		defer mu.Unlock()

		reported = append(reported, stats.Violations...)
	}

	paths := []string{"/sys/fs/cgroup/buildkit", "/sys/fs/cgroup/init"}

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, paths, quietLog(), report, 150*time.Millisecond,
		WithBuildKitRegistry(reg), WithBuildPolicySource(src), WithBuildKitRunLevel(5), WithBuildKitDNSUpstreams([]string{"10.96.0.10:53"}),
		WithSessionLookup(func(time.Time) ([]SessionState, bool) { return nil, false }),
		WithBindingLookup(func(id uint64, at time.Time) (CgroupBinding, bool) { return reg.LookupForEvent(id, at) }),
		WithJoinPendingWindow(0))
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	dp := plat.dp

	dp.mu.Lock()
	if len(dp.attached) != 2 || dp.cfg.RunLevel != 5 || len(dp.cfg.ParentIDs) != 2 || len(dp.ancestors) != 2 || len(dp.cfg.DNSUpstreams) != 1 {
		t.Fatalf("attached=%v cfg=%+v ancestors=%v", dp.attached, dp.cfg, dp.ancestors)
	}

	ring := dp.ring
	dp.mu.Unlock()

	if attach.handle != nil {
		t.Fatal("slot path must not load the per-pod handle")
	}

	if plat.fakePlatform.ebpfLoaded {
		t.Fatal("per-pod LoadEBPF called")
	}

	// A row from the still-PENDING cgroup 77 (as the reader would record it).
	ring(77).RecordViolation(Violation{
		CgroupID: 77, IP: "6.6.6.6", Port: 443, PID: 9, Action: "packet_observed",
		Timestamp: time.Now(), EnforcementState: EnfStatePendingBind,
	})

	// The join then links 77 to project a: the binder installs the slot.
	reg.LinkCgroup(77, CgroupBinding{
		SessionRef: "r1", ContainerID: "c77",
		FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "build"},
		Strength:      StrengthExactArgv, CandidateKeys: []PolicyKey{{"g/a", "build"}},
	})

	if p, ok := dp.cg(77); !ok || p.State != bkStateBound || p.Mode != bkModeBlock {
		t.Fatalf("cgroup entry = %+v ok=%v", p, ok)
	}

	deadline := time.Now().Add(3 * time.Second)

	var got []Violation

	for time.Now().Before(deadline) {
		mu.Lock()
		got = append([]Violation(nil), reported...)
		mu.Unlock()

		if len(got) > 0 {
			break
		}

		time.Sleep(20 * time.Millisecond)
	}

	if len(got) != 1 {
		t.Fatalf("reported %d rows, want 1", len(got))
	}

	v := got[0]
	if !v.WouldBlock || v.EnforcementState != EnfStatePendingBind || v.PolicyKey != "g/a@1/build" ||
		v.BindingStrength != StrengthExactArgv || v.BindingVerified || v.BuildProjectPath != "g/a" {
		t.Fatalf("row = %+v", v)
	}

	if err = attach.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if reg.obs() != nil {
		t.Fatal("binder observer left installed after Close")
	}

	if !dp.closed {
		t.Fatal("datapath not closed")
	}
}

func TestSlotAttach_SeedsFromExistingBindings(t *testing.T) {
	t.Parallel()

	plat := &fakeBKPlatform{fakePlatform: &fakePlatform{}, dp: newFakeDP()}
	reg := NewSessionRegistry(time.Minute)
	reg.SetHistoryConnected(true)
	reg.LinkCgroup(5, CgroupBinding{
		SessionRef: "r1", ContainerID: "c5",
		FrontendAttrs: map[string]string{FrontendAttrKeyProjectPath: "g/a", FrontendAttrKeyJobName: "build"},
		Strength:      StrengthExactArgv, CandidateKeys: []PolicyKey{{"g/a", "build"}},
	})

	src := newFakeSource()
	src.set("g/a", "build", enforcePol(1, "1.1.1.1"))

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, quietLog(), nil, 0,
		WithBuildKitRegistry(reg), WithBuildPolicySource(src), WithBuildKitRunLevel(2))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	if p, ok := plat.dp.cg(5); !ok || p.State != bkStateBound {
		t.Fatalf("existing binding not seeded: %+v ok=%v", p, ok)
	}
}

func TestSlotAttach_NoRegistryMeansAuditOnly(t *testing.T) {
	t.Parallel()

	plat := &fakeBKPlatform{fakePlatform: &fakePlatform{}, dp: newFakeDP()}

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, quietLog(), nil, 0,
		WithBuildKitRunLevel(2))
	if err != nil {
		t.Fatal(err)
	}

	if attach.binder != nil {
		t.Fatal("binder created without a registry")
	}

	if err = attach.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSlotAttach_TrustedCIDRsPassedThrough(t *testing.T) {
	t.Parallel()

	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	plat := &fakeBKPlatform{fakePlatform: &fakePlatform{}, dp: newFakeDP()}

	attach, err := StartBuildKitEgressAttach(t.Context(), plat, []string{"/sys/fs/cgroup/buildkit"}, quietLog(), nil, 0,
		WithBuildKitRunLevel(2), WithBuildKitTrustedCIDRs([]net.IPNet{*n}))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = attach.Close() })

	if len(plat.trusted) != 1 {
		t.Fatalf("trusted = %v", plat.trusted)
	}
}
