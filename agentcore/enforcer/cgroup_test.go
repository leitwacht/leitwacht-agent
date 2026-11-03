//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindCgroupByID(t *testing.T) {
	// Create a fake cgroup tree:
	// root/
	//   besteffort/
	//     pod-abc/
	//       container-111/
	//       container-222/
	//   burstable/
	//     pod-xyz/
	//       container-333/
	root := t.TempDir()

	dirs := []string{
		"besteffort/pod-abc/container-111",
		"besteffort/pod-abc/container-222",
		"burstable/pod-xyz/container-333",
	}
	for _, d := range dirs {
		err := os.MkdirAll(filepath.Join(root, d), 0o755)
		if err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name        string
		containerID string
		wantSuffix  string
		wantErr     bool
	}{
		{
			name:        "find in besteffort",
			containerID: "container-111",
			wantSuffix:  "besteffort/pod-abc/container-111",
		},
		{
			name:        "find in burstable",
			containerID: "container-333",
			wantSuffix:  "burstable/pod-xyz/container-333",
		},
		{
			name:        "find second container in same pod",
			containerID: "container-222",
			wantSuffix:  "besteffort/pod-abc/container-222",
		},
		{
			name:        "not found",
			containerID: "container-999999",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findCgroupByID(root, tt.containerID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			want := filepath.Join(root, tt.wantSuffix)
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestFindCgroupByID_EmptyTree(t *testing.T) {
	root := t.TempDir()

	_, err := findCgroupByID(root, "container-abc123def456")
	if err == nil {
		t.Fatal("expected error for empty tree")
	}
}

func TestFindCgroupByID_MissingRoot(t *testing.T) {
	_, err := findCgroupByID("/nonexistent/cgroup/path", "container-abc123def456")
	if err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestFindCgroupByIDIn_SystemdRoots(t *testing.T) {
	t.Parallel()

	for _, top := range []string{
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0a1b2c3d_1111_2222_3333_444455556666.slice",
		"kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod0a1b2c3d_1111_2222_3333_444455556666.slice",
	} {
		mount := t.TempDir()
		scope := "cri-containerd-abc123.scope"

		if err := os.MkdirAll(filepath.Join(mount, top, scope), 0o750); err != nil {
			t.Fatal(err)
		}

		got, err := findCgroupByIDIn(podCgroupRoots(mount), scope)
		if err != nil {
			t.Fatalf("%s: %v", top, err)
		}

		if got != filepath.Join(mount, top, scope) {
			t.Fatalf("got %q", got)
		}
	}
}

func TestFindCgroupByIDIn_NotFoundAndDepthBound(t *testing.T) {
	t.Parallel()

	mount := t.TempDir()
	deep := filepath.Join(mount, "kubepods.slice", "a", "b", "c", "d", "e", "f", "g", "target")

	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := findCgroupByIDIn(podCgroupRoots(mount), "target"); err == nil {
		t.Fatal("expected depth bound to hide a too-deep match")
	}

	if _, err := findCgroupByIDIn(podCgroupRoots(mount), "missing"); err == nil {
		t.Fatal("expected not found")
	}
}
