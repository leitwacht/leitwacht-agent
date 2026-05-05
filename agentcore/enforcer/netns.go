//go:build linux

package enforcer

import (
	"fmt"
	"runtime"

	"github.com/vishvananda/netns"
)

// inNetns executes fn inside the network namespace of the given PID.
// The calling goroutine is locked to its OS thread for the duration.
// The original namespace is always restored, even if fn returns an error.
//
// IMPORTANT: fn must not spawn goroutines — they would run on different
// OS threads in the host namespace, not the target namespace.
func inNetns(pid int, fn func() error) error {
	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	origNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer origNs.Close()    //nolint:errcheck // cleanup
	defer netns.Set(origNs) //nolint:errcheck // best-effort restore

	targetNs, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("get netns for pid %d: %w", pid, err)
	}
	defer targetNs.Close() //nolint:errcheck // cleanup

	err = netns.Set(targetNs)
	if err != nil {
		return fmt.Errorf("set netns for pid %d: %w", pid, err)
	}

	return fn()
}
