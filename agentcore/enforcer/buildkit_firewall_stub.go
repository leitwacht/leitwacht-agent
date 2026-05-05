//go:build !linux

package enforcer

import "net"

// isLoopbackOrUnspecified mirrors the Linux implementation for cross-platform
// builds (darwin/test toolchains). The BuildKit DNS firewall itself is only
// installed on Linux via LinuxPlatform, but buildkit.go uses this helper to
// decide whether to record firewallInstalled after SetupBuildkitDNSFirewall
// returns — that code path runs on every platform through the Platform
// interface, so the helper needs a non-Linux stub.
func isLoopbackOrUnspecified(ip net.IP) bool {
	if ip == nil {
		return true
	}

	return ip.IsLoopback() || ip.IsUnspecified()
}
