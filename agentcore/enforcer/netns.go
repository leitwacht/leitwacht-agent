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
	targetNs, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("get netns for pid %d: %w", pid, err)
	}
	defer targetNs.Close() //nolint:errcheck // cleanup

	return inNetnsHandle(targetNs, fn)
}

// inNetnsHandle is inNetns for an already-open netns handle, so the target
// namespace stays reachable after every process that was in it has exited.
//
// The work runs in a dedicated goroutine whose result is passed back on a
// channel. If the original namespace cannot be restored that goroutine exits
// while still locked to its thread, so the Go runtime discards the thread at
// once; the caller never continues on a thread stuck in the job netns.
func inNetnsHandle(target netns.NsHandle, fn func() error) error {
	done := make(chan error, 1)

	go func() { done <- inNetnsHandleLocked(target, fn) }()

	return <-done
}

func inNetnsHandleLocked(target netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()

	origNs, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()

		return fmt.Errorf("get current netns: %w", err)
	}
	defer origNs.Close() //nolint:errcheck // cleanup

	err = netns.Set(target)
	if err != nil {
		// Never left the original namespace; the thread is safe to reuse.
		runtime.UnlockOSThread()

		return fmt.Errorf("set netns: %w", err)
	}

	fnErr := fn()

	if restoreErr := netns.Set(origNs); restoreErr != nil {
		// Do NOT unlock: the thread dies with this goroutine.
		return fmt.Errorf("restore netns: %w", restoreErr)
	}

	runtime.UnlockOSThread()

	return fnErr
}
