//go:build !linux

package procenv

// namesLinux is a stub for non-Linux builds. The agent itself is
// Linux-only at runtime; this stub keeps editing/testing on macOS
// straightforward.
func namesLinux(_ int) []string {
	return nil
}
