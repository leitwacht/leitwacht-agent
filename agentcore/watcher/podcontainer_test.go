//go:build linux

package watcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const testPodUID = "12345678-1234-1234-1234-123456789abc"

func lbl(ns, name, uid string) map[string]string {
	return map[string]string{
		"io.kubernetes.pod.namespace":  ns,
		"io.kubernetes.container.name": name,
		"io.kubernetes.pod.uid":        uid,
	}
}

func procWithCgroup(t *testing.T, root, pid, cgroup string) {
	t.Helper()

	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroup+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixedList(cs ...podContainer) listPodContainers {
	return func(context.Context) ([]podContainer, error) { return cs, nil }
}

func TestFindPodContainerPID(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	procWithCgroup(t, root, "100", "/kubepods/pod"+testPodUID+"/ctr")
	procWithCgroup(t, root, "101", "/kubepods/pod12345678_1234_1234_1234_123456789abc/ctr")
	procWithCgroup(t, root, "200", "/kubepods/podffffffff-0000-0000-0000-000000000000/ctr")

	good := podContainer{ID: "a", Labels: lbl("buildkitd", "buildkitd", testPodUID), Running: true, PID: 100}
	ctx := context.Background()

	pid, uid, err := findPodContainerPID(ctx, fixedList(
		podContainer{ID: "x", Labels: lbl("other", "buildkitd", testPodUID), Running: true, PID: 200},
		podContainer{ID: "y", Labels: lbl("buildkitd", "sidecar", testPodUID), Running: true, PID: 200},
		podContainer{ID: "z", Labels: lbl("buildkitd", "buildkitd", testPodUID), Running: false, PID: 200},
		good,
	), root, "buildkitd", "buildkitd")
	if err != nil || pid != 100 || uid != testPodUID {
		t.Fatalf("pid %d uid %q err %v, want 100", pid, uid, err)
	}

	// Underscore-form (systemd) cgroup path also matches.
	under := good
	under.PID = 101

	if pid, _, err = findPodContainerPID(ctx, fixedList(under), root, "buildkitd", "buildkitd"); err != nil || pid != 101 {
		t.Fatalf("underscore form: pid %d err %v", pid, err)
	}

	// Two running matches: ambiguous.
	second := good
	second.ID = "b"

	if _, _, err = findPodContainerPID(ctx, fixedList(good, second), root, "buildkitd", "buildkitd"); !errors.Is(err, ErrPodContainerAmbiguous) {
		t.Fatalf("err %v, want ambiguous", err)
	}

	// A sandbox container carrying the same labels is ignored.
	sb := good
	sb.ID = "s"
	sb.Labels = lbl("buildkitd", "buildkitd", testPodUID)
	sb.Labels["io.cri-containerd.kind"] = "sandbox"

	if pid, _, err = findPodContainerPID(ctx, fixedList(sb, good), root, "buildkitd", "buildkitd"); err != nil || pid != 100 {
		t.Fatalf("sandbox not ignored: pid %d err %v", pid, err)
	}

	// None running.
	stopped := good
	stopped.Running = false

	if _, _, err = findPodContainerPID(ctx, fixedList(stopped), root, "buildkitd", "buildkitd"); !errors.Is(err, ErrPodContainerNotFound) {
		t.Fatalf("err %v, want not found", err)
	}

	// Cgroup of the task belongs to another pod.
	bad := good
	bad.PID = 200

	if _, _, err = findPodContainerPID(ctx, fixedList(bad), root, "buildkitd", "buildkitd"); !errors.Is(err, ErrPodContainerCgroup) {
		t.Fatalf("err %v, want cgroup mismatch", err)
	}

	// Missing pod UID label.
	nouid := good
	nouid.Labels = lbl("buildkitd", "buildkitd", "")

	if _, _, err = findPodContainerPID(ctx, fixedList(nouid), root, "buildkitd", "buildkitd"); !errors.Is(err, ErrPodContainerCgroup) {
		t.Fatalf("err %v, want error without a pod uid", err)
	}

	// List failure propagates.
	boom := errors.New("boom")

	if _, _, err = findPodContainerPID(ctx, func(context.Context) ([]podContainer, error) { return nil, boom }, root, "a", "b"); !errors.Is(err, boom) {
		t.Fatalf("err %v, want list error", err)
	}
}

func TestFindPodContainerPID_RejectsFilterSyntax(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{`a"b`, "a,b", "A", "a==b", ""} {
		if _, _, err := FindPodContainerPID(context.Background(), "/nonexistent.sock", "k8s.io", bad, "buildkitd"); !errors.Is(err, ErrPodContainerConfig) {
			t.Fatalf("namespace %q: err %v, want rejection before connecting", bad, err)
		}
	}
}
