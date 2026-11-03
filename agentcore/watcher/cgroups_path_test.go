package watcher

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestResolveCgroupsPathAt(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mount := t.TempDir()
	sl := "kubepods-burstable-pod0a1b2c3d_1111_2222_3333_444455556666.slice"
	dir := filepath.Join(mount, "kubepods.slice", "kubepods-burstable.slice", sl, "cri-containerd-abc.scope")

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		linux *specs.Linux
		want  string
	}{
		{"nil linux", nil, ""},
		{"empty", &specs.Linux{}, ""},
		{"systemd existing", &specs.Linux{CgroupsPath: sl + ":cri-containerd:abc"}, dir},
		{"systemd missing dir", &specs.Linux{CgroupsPath: sl + ":cri-containerd:gone"}, ""},
		{"resolve error", &specs.Linux{CgroupsPath: "/a/../../b"}, ""},
		{"relative rejected", &specs.Linux{CgroupsPath: "kubepods/x"}, ""},
		{"rootless user manager unsupported",
			&specs.Linux{CgroupsPath: "user-1000.slice:podman:abc"}, ""},
	}
	for _, c := range cases {
		if got := resolveCgroupsPathAt(logger, mount, "abc", c.linux); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
