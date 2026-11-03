package cgrouppath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const uid = "0a1b2c3d_1111_2222_3333_444455556666"

func TestResolve(t *testing.T) {
	t.Parallel()

	m := "/sys/fs/cgroup"
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"systemd burstable kubelet.slice",
			"kubelet-kubepods-burstable-pod" + uid + ".slice:cri-containerd:abc123",
			m + "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod" + uid + ".slice/cri-containerd-abc123.scope", false},
		{"systemd besteffort plain",
			"kubepods-besteffort-pod" + uid + ".slice:cri-containerd:abc",
			m + "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + uid + ".slice/cri-containerd-abc.scope", false},
		{"systemd guaranteed plain",
			"kubepods-pod" + uid + ".slice:cri-containerd:abc",
			m + "/kubepods.slice/kubepods-pod" + uid + ".slice/cri-containerd-abc.scope", false},
		{"systemd guaranteed kubelet.slice",
			"kubelet-kubepods-pod" + uid + ".slice:crio:abc",
			m + "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + uid + ".slice/crio-abc.scope", false},
		{"systemd sandbox slice name",
			"kubepods-burstable.slice:cri-containerd:x.slice",
			m + "/kubepods.slice/kubepods-burstable.slice/x.slice", false},
		{"systemd empty slice", ":docker:abc", m + "/system.slice/docker-abc.scope", false},
		{"cgroupfs absolute", "/kubepods/burstable/pod" + uid + "/abc", m + "/kubepods/burstable/pod" + uid + "/abc", false},
		{"cgroupfs relative rejected", "kubepods/pod" + uid + "/abc", "", true},
		{"empty prefix rejected", "a.slice::n", "", true},
		{"system.slice docker", "system.slice:docker:abc", m + "/system.slice/docker-abc.scope", false},
		{"machine.slice libpod", "machine.slice:libpod:abc", m + "/machine.slice/libpod-abc.scope", false},
		{"root slice", "-.slice:p:n", m + "/p-n.scope", false},
		{"escaped dash slice literal", `my\x2dapp.slice:p:n`, m + `/my\x2dapp.slice/p-n.scope`, false},
		// Rootless user-manager units resolve to a path that does not exist
		// under the mount layout; the watcher then falls back to the PID.
		{"rootless user manager unsupported", "user.slice:podman:abc",
			m + "/user.slice/podman-abc.scope", false},
		{"empty", "", "", true},
		{"root", "/", "", true},
		{"dotdot abs", "/kubepods/../../etc", "", true},
		{"dotdot rel", "../x", "", true},
		{"dotdot systemd name", "a.slice:p:../../x", "", true},
		{"slash in name", "a.slice:p:x/y", "", true},
		{"slash in slice", "/etc/a.slice:p:x", "", true},
		{"too many colons", "a.slice:p:n:x", "", true},
		{"one colon", "a.slice:p", "", true},
		{"not a slice", "foo:p:n", "", true},
		{"empty name", "a.slice:p:", "", true},
		{"empty segment", "a--b.slice:p:n", "", true},
		{"nul", "a\x00b", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got, err := Resolve("", c.in)
			if c.wantErr {
				if err == nil || !errors.Is(err, ErrInvalidPath) {
					t.Fatalf("want ErrInvalidPath, got %q, %v", got, err)
				}

				return
			}

			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

func TestResolveExistsInFakeTree(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	in := "kubelet-kubepods-burstable-pod" + uid + ".slice:cri-containerd:abc"

	want, err := Resolve(root, in)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(want, 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := Resolve(root, in)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(got); err != nil {
		t.Fatalf("resolved path missing: %v", err)
	}

	if filepath.Dir(filepath.Dir(got)) != filepath.Join(root, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-burstable.slice") {
		t.Fatalf("unexpected nesting: %s", got)
	}
}
