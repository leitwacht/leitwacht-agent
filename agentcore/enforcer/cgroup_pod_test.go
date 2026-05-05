package enforcer

import (
	"errors"
	"testing"
)

func TestPodCgroupFromContainer(t *testing.T) {
	const (
		burstableSlice = "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
			"kubepods-burstable-pod9e3c2d70_7e1a_4cb4_8ab9_c7a5f1d2e3b4.slice"
		besteffortSlice = "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
			"kubepods-besteffort-poddeadbeef_dead_beef_dead_beefdeadbeef.slice"
		guaranteedSlice = "/sys/fs/cgroup/kubepods.slice/" +
			"kubepods-pod9e3c2d70_7e1a_4cb4_8ab9_c7a5f1d2e3b4.slice"
		mixedCaseSlice = "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
			"kubepods-burstable-pod9E3C2D70_7e1a_4CB4_8ab9_c7a5f1d2e3b4.slice"
	)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "systemd burstable",
			in:   burstableSlice + "/cri-containerd-abc.scope",
			want: burstableSlice,
		},
		{
			name: "systemd besteffort",
			in:   besteffortSlice + "/cri-containerd-xyz.scope",
			want: besteffortSlice,
		},
		{
			name: "systemd guaranteed (no QoS segment)",
			in:   guaranteedSlice + "/cri-containerd-abc.scope",
			want: guaranteedSlice,
		},
		{
			name: "cgroupfs burstable",
			in:   "/sys/fs/cgroup/kubepods/burstable/pod9e3c2d70-7e1a-4cb4-8ab9-c7a5f1d2e3b4/abc123",
			want: "/sys/fs/cgroup/kubepods/burstable/pod9e3c2d70-7e1a-4cb4-8ab9-c7a5f1d2e3b4",
		},
		{
			name: "cgroupfs besteffort",
			in:   "/sys/fs/cgroup/kubepods/besteffort/pod00000000-1111-2222-3333-444444444444/abc",
			want: "/sys/fs/cgroup/kubepods/besteffort/pod00000000-1111-2222-3333-444444444444",
		},
		{
			name: "mixed case UUID",
			in:   mixedCaseSlice + "/cri-containerd-abc.scope",
			want: mixedCaseSlice,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PodCgroupFromContainer(tt.in)
			if err != nil {
				t.Fatalf("PodCgroupFromContainer(%q) returned error: %v", tt.in, err)
			}

			if got != tt.want {
				t.Errorf("PodCgroupFromContainer(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPodCgroupFromContainer_NotPodShape(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "root", in: "/"},
		{name: "docker", in: "/sys/fs/cgroup/docker/abc123def456"},
		{name: "docker systemd", in: "/sys/fs/cgroup/docker.slice/docker-abc123.scope"},
		{name: "podman user", in: "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/podman.scope"},
		{name: "systemd user session", in: "/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope"},
		{
			name: "qos slice (parent is QoS, not pod)",
			in: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
				"kubepods-burstable-podGARBAGE.slice",
		},
		{name: "kubepods top-level", in: "/sys/fs/cgroup/kubepods.slice"},
		{name: "malformed pod uid", in: "/kubepods.slice/kubepods-burstable-podNOTAUUID.slice/scope"},
		{name: "plain containerd ctr", in: "/sys/fs/cgroup/default/myctr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PodCgroupFromContainer(tt.in)
			if !errors.Is(err, ErrNotPodShape) {
				t.Fatalf("PodCgroupFromContainer(%q) = (%q, %v), want ErrNotPodShape", tt.in, got, err)
			}
		})
	}
}

// TestPodCgroupFromContainer_ParentIsQosSlice asserts that the parent must
// match a pod-UID, not a QoS slice — preventing accidental attach at the
// QoS level (which would filter every pod of that QoS class).
func TestPodCgroupFromContainer_ParentIsQosSlice(t *testing.T) {
	// A path whose parent IS a QoS slice (not a pod slice) — would only
	// happen with malformed input but the regex must reject it.
	in := "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/something-not-a-pod.scope"

	_, err := PodCgroupFromContainer(in)
	if !errors.Is(err, ErrNotPodShape) {
		t.Fatalf("PodCgroupFromContainer(%q) accepted a QoS slice as pod cgroup; got err=%v", in, err)
	}
}
