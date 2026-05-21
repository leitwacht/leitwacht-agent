//go:build linux

package enforcer

import (
	"fmt"
	"syscall"
)

// nullTerminated returns the string representation of a byte slice up to
// the first null byte. Used to decode BPF char arrays (comm, path) that
// are padded with zeros.
func nullTerminated(buf []byte) string {
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}

	return string(buf)
}

// cgroupID returns the cgroup ID (inode number) for the given cgroup path.
func cgroupID(cgroupPath string) (uint64, error) {
	var st syscall.Stat_t

	err := syscall.Stat(cgroupPath, &st)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}

	return st.Ino, nil
}
