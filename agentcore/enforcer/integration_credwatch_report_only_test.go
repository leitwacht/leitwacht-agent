//go:build linux && integration

package enforcer

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestIntegrationCredwatchReportOnlyClass runs a real container in
// enforce mode and checks the three behaviours the report-only class
// promises: a report-only path opens fine and is reported, a watched
// path is denied with EPERM, and a path listed in both classes is
// report-only (precedence). Rename of a report-only file is allowed and
// reported; rename of a watched file is denied.
//
// Needs root, BPF LSM and podman (or ctr). Run:
// sudo -E go test ./agentcore/enforcer/ -tags integration -run TestIntegrationCredwatchReportOnlyClass -v -count=1.
//
//nolint:cyclop,funlen // sequential kernel + container steps
func TestIntegrationCredwatchReportOnlyClass(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	objs, lsmLink, err := loadCredwatchLSM()
	if err != nil {
		t.Skip("eBPF/LSM not available: ", err)
	}
	defer lsmLink.Close() //nolint:errcheck // test cleanup

	for _, l := range attachCredwatchPathHooks(objs, testLogger()) {
		defer l.Close() //nolint:errcheck // test cleanup
	}
	defer objs.Close() //nolint:errcheck // test cleanup

	// /.docker/config.json is in BOTH lists: report-only must win.
	if err = populateWatchedPathMaps(objs,
		[]string{"/.aws/credentials", "/.docker/config.json"},
		[]string{"/.docker/config.json", "/.npmrc"},
		nil); err != nil {
		t.Fatalf("populateWatchedPathMaps: %v", err)
	}

	var (
		mu     sync.Mutex
		events []credwatchEventBPF
	)

	stop, err := startCredwatchReader(objs, testLogger(), func(e credwatchEventBPF) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("startCredwatchReader: %v", err)
	}
	defer stop()

	// The script creates the files, waits for the test to put its
	// cgroup in enforce mode, then probes each path and records the
	// outcome under /tmp/r-<name>.
	script := `set -u
mkdir -p /root/.docker /root/.aws
echo x > /root/.docker/config.json
echo x > /root/.aws/credentials
echo x > /root/.npmrc
echo x > /root/.aws/keep
sleep 6
probe() { if cat "$2" > /dev/null 2>/tmp/err; then echo ok > "/tmp/r-$1"; else echo denied > "/tmp/r-$1"; fi; }
probe docker /root/.docker/config.json
probe npmrc /root/.npmrc
probe aws /root/.aws/credentials
if mv /root/.npmrc /root/.npmrc2 2>/dev/null; then echo ok > /tmp/r-mv-npmrc; else echo denied > /tmp/r-mv-npmrc; fi
if mv /root/.aws/credentials /root/.aws/c2 2>/dev/null; then echo ok > /tmp/r-mv-aws; else echo denied > /tmp/r-mv-aws; fi
echo done > /tmp/r-done
sleep 120`

	name := "lw-credwatch-ro-test"
	pid := startTestContainer(t, name, script)

	cgPath, err := getCgroupPath(pid)
	if err != nil {
		t.Fatalf("cgroup path: %v", err)
	}

	var st syscall.Stat_t
	if err = syscall.Stat(cgPath, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	cgID := st.Ino

	// Enforce mode: not observe-only, not exempt.
	if err = populateCredwatchMaps(objs, cgID, false, false); err != nil {
		t.Fatalf("populateCredwatchMaps: %v", err)
	}
	defer removeCredwatchMaps(objs, cgID)

	deadline := time.Now().Add(40 * time.Second)

	for time.Now().Before(deadline) {
		if containerFile(name, "/tmp/r-done") == "done" {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	want := map[string]string{
		"docker":   "ok",     // report-only beats watched
		"npmrc":    "ok",     // report-only
		"aws":      "denied", // watched, enforce
		"mv-npmrc": "ok",     // rename of a report-only file
		"mv-aws":   "denied", // rename of a watched file
	}

	for k, v := range want {
		if got := containerFile(name, "/tmp/r-"+k); got != v {
			t.Errorf("%s: got %q, want %q", k, got, v)
		}
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	seen := map[string]bool{}

	for _, e := range events {
		if e.CgroupID != cgID {
			continue
		}

		p := nullTerminated(e.Path[:])
		ro := credwatchKindReportOnlyFlag(e.Kind)
		reason := credwatchReason(e.Kind)
		t.Logf("event: reason=%s report_only=%v path=%q", reason, ro, p)

		switch {
		case strings.HasSuffix(p, "/.docker/config.json") && reason == "open":
			seen["docker-open"] = ro
		case strings.HasSuffix(p, "/.npmrc") && reason == "open":
			seen["npmrc-open"] = ro
		case strings.HasSuffix(p, "/.aws/credentials") && reason == "open":
			seen["aws-open"] = ro
		case p == ".npmrc" && reason == "rename":
			seen["npmrc-rename"] = ro
		case p == "credentials" && reason == "rename":
			seen["aws-rename"] = ro
		}
	}

	for k, wantRO := range map[string]bool{
		"docker-open": true, "npmrc-open": true, "aws-open": false,
		"npmrc-rename": true, "aws-rename": false,
	} {
		got, ok := seen[k]
		if !ok {
			t.Errorf("no %s event", k)

			continue
		}

		if got != wantRO {
			t.Errorf("%s: report_only=%v, want %v", k, got, wantRO)
		}
	}
}

// containerFile returns the trimmed contents of path inside the named
// test container, or "" when absent.
func containerFile(name, path string) string {
	var out []byte

	var err error

	if _, lookErr := exec.LookPath("ctr"); lookErr == nil {
		out, err = exec.Command("ctr", "task", "exec", "--exec-id", "r"+strings.ReplaceAll(path, "/", "-"), name, "cat", path).Output()
	} else {
		out, err = exec.Command("podman", "exec", name, "cat", path).Output()
	}

	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
