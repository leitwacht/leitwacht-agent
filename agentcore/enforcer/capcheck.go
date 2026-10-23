package enforcer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// capNetAdmin is CAP_NET_ADMIN's bit number (linux/capability.h).
const capNetAdmin = 12

// procHasCapNetAdmin reports whether pid's effective capability set
// includes CAP_NET_ADMIN, read from /proc/<pid>/status (CapEff).
//
// A process with CAP_NET_ADMIN can stamp SO_MARK itself and so slip past the
// netns DNS redirect and the embedded-resolver guard, both of which trust the
// agent's mark; it can also edit the nftables rules outright. That
// configuration cannot be enforced by this agent, so callers surface it as a
// warning.
func procHasCapNetAdmin(pid int) (bool, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false, fmt.Errorf("open status: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "CapEff:")
		if !ok {
			continue
		}

		mask, parseErr := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if parseErr != nil {
			return false, fmt.Errorf("parse CapEff: %w", parseErr)
		}

		return mask&(1<<capNetAdmin) != 0, nil
	}

	return false, fmt.Errorf("CapEff not found in /proc/%d/status", pid) //nolint:err113 // one-off diagnostic
}

// shortID truncates a container ID for log fields without risking a panic
// on short input.
func shortID(id string) string {
	return id[:min(len(id), 12)]
}
