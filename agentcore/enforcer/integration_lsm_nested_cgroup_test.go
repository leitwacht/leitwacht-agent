//go:build linux && integration

package enforcer

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// startPrivilegedPodmanContainer boots a detached privileged alpine
// container with a private cgroup namespace (so /sys/fs/cgroup is a
// writable view of the container's own cgroup) and returns its host PID.
// Podman only: the nested-cgroup scenario needs a writable cgroupfs.
func startPrivilegedPodmanContainer(t *testing.T, name, script string) int {
	t.Helper()

	const testImage = "docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"

	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found")
	}

	_ = exec.Command("podman", "rm", "-f", name).Run()

	out, err := exec.Command("podman", "run", "-d", "--log-driver=none", "--pull=missing",
		"--privileged", "--cgroupns=private", "--name", name, testImage, "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("podman run: %v\n%s", err, out)
	}

	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", name).Run() })

	pidOut, err := exec.Command("podman", "inspect", "-f", "{{.State.Pid}}", name).Output()
	if err != nil {
		t.Fatalf("podman inspect: %v", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	if err != nil {
		t.Fatalf("parse pid %q: %v", pidOut, err)
	}

	return pid
}

// TestIntegrationLSMNestedCgroup is the regression test for the
// descendant-cgroup bypass: a process that mkdirs a child cgroup (three
// levels deep) under a monitored container and moves itself into it must
// still have its credential reads and /proc/<pid>/mem opens denied, and
// the events must be attributed to the container's cgroup.
//
// Run: sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationLSMNestedCgroup -v -count=1.
//
//nolint:cyclop,funlen // sequential kernel + container steps
func TestIntegrationLSMNestedCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	cwObjs, cwLink, err := loadCredwatchLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer cwLink.Close() //nolint:errcheck // test cleanup
	defer cwObjs.Close() //nolint:errcheck // test cleanup

	pmObjs, pmLink, err := loadProcMemLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer pmLink.Close() //nolint:errcheck // test cleanup
	defer pmObjs.Close() //nolint:errcheck // test cleanup

	if err = populateWatchedPathMaps(cwObjs, []string{"/.aws/credentials"}, nil, nil); err != nil {
		t.Fatalf("populateWatchedPathMaps: %v", err)
	}

	var (
		mu       sync.Mutex
		cwEvents []credwatchEventBPF
		pmEvents []procMemEventBPF
	)

	stopCW, err := startCredwatchReader(cwObjs, testLogger(), func(e credwatchEventBPF) {
		mu.Lock()
		cwEvents = append(cwEvents, e)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("startCredwatchReader: %v", err)
	}
	defer stopCW()

	stopPM, err := startProcMemReader(pmObjs, testLogger(), func(e procMemEventBPF) {
		mu.Lock()
		pmEvents = append(pmEvents, e)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("startProcMemReader: %v", err)
	}
	defer stopPM()

	script := `set -u
mkdir -p /root/.aws
echo x > /root/.aws/credentials
sleep 6
probe() { if true < "$2" 2>/dev/null; then echo ok > "/tmp/r-$1"; else echo denied > "/tmp/r-$1"; fi; }
probe aws-root /root/.aws/credentials
probe mem-root /proc/self/mem
mkdir -p /sys/fs/cgroup/n1/n2/n3 || echo mkdir-failed > /tmp/r-setup
echo $$ > /sys/fs/cgroup/n1/n2/n3/cgroup.procs || echo move-failed > /tmp/r-setup
grep -q n3 /proc/self/cgroup || echo not-nested > /tmp/r-setup
probe aws-nested /root/.aws/credentials
probe mem-nested /proc/self/mem
echo done > /tmp/r-done
sleep 120`

	name := "lw-lsm-nested-cgroup-test"
	pid := startPrivilegedPodmanContainer(t, name, script)

	cgPath, err := getCgroupPath(pid)
	if err != nil {
		t.Fatalf("cgroup path: %v", err)
	}

	var st syscall.Stat_t
	if err = syscall.Stat(cgPath, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	cgID := st.Ino

	// Enforce mode, not exempt. Only the container's own cgroup is
	// registered: the nested children are NOT, which is the point.
	if err = populateCredwatchMaps(cwObjs, cgID, false, false); err != nil {
		t.Fatalf("populateCredwatchMaps: %v", err)
	}
	defer removeCredwatchMaps(cwObjs, cgID)

	if err = populateProcMemMaps(pmObjs, cgID, false, false); err != nil {
		t.Fatalf("populateProcMemMaps: %v", err)
	}
	defer removeProcMemMaps(pmObjs, cgID)

	deadline := time.Now().Add(40 * time.Second)

	for time.Now().Before(deadline) {
		if containerFile(name, "/tmp/r-done") == "done" {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	if s := containerFile(name, "/tmp/r-setup"); s != "" {
		t.Fatalf("test setup failed in container: %s", s)
	}

	for k, v := range map[string]string{
		"aws-root":   "denied", // baseline: container cgroup itself
		"mem-root":   "denied",
		"aws-nested": "denied", // the regression: 3 levels below
		"mem-nested": "denied",
	} {
		if got := containerFile(name, "/tmp/r-"+k); got != v {
			t.Errorf("%s: got %q, want %q", k, got, v)
		}
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var cwNested, pmNested int

	for _, e := range cwEvents {
		if e.ContainerCgroupID != cgID {
			continue
		}

		if e.CgroupID != cgID {
			cwNested++
		}
	}

	for _, e := range pmEvents {
		if e.ContainerCgroupID != cgID {
			continue
		}

		if e.CgroupID != cgID {
			pmNested++
		}
	}

	t.Logf("nested events: credwatch=%d proc_mem=%d (of %d / %d)", cwNested, pmNested, len(cwEvents), len(pmEvents))

	if cwNested == 0 {
		t.Error("no credwatch event from the nested cgroup attributed to the container cgroup")
	}

	if pmNested == 0 {
		t.Error("no proc_mem event from the nested cgroup attributed to the container cgroup")
	}
}
