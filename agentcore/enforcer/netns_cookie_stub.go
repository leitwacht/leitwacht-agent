//go:build !linux

package enforcer

import (
	"log/slog"
	"net"
)

// netnsCookieFromConn is a stub on non-Linux. Always returns 0, which
// in turn makes every DNS PID lookup miss — matching the DNSPIDTracker
// stub's behaviour. DNS proxy still serves, just without attribution.
func netnsCookieFromConn(_ net.PacketConn, _ *slog.Logger) uint64 {
	return 0
}
