//go:build linux

package enforcer

import (
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func waitBinaryPath(tr *DNSPIDTracker, pid uint32, ok func(string) bool) (string, bool) {
	var got string

	for range 40 {
		got = tr.BinaryPathForPID(pid)
		if ok(got) {
			return got, true
		}

		time.Sleep(50 * time.Millisecond)
	}

	return got, false
}

// A re-exec must replace the recorded path, and process exit must drop
// the entry so a recycled pid cannot inherit it.
func TestDNSPIDProcessInfoReexecAndExit(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	tr, err := NewDNSPIDTracker(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Skip("dns_pid tracker unavailable: ", err)
	}

	defer tr.Close()

	cmd := exec.Command("sh", "-c", "sleep 0.5; exec sleep 30")
	if err = cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	pid := uint32(cmd.Process.Pid) //nolint:gosec // pid fits uint32

	if got, ok := waitBinaryPath(tr, pid, func(p string) bool { return strings.HasSuffix(p, "/sleep") }); !ok {
		_ = cmd.Process.Kill()

		t.Fatalf("after re-exec want path ending /sleep, got %q", got)
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	if got, ok := waitBinaryPath(tr, pid, func(p string) bool { return p == "" }); !ok {
		t.Fatalf("process_info entry survived process exit: %q", got)
	}
}
