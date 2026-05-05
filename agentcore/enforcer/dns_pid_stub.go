//go:build !linux

package enforcer

// DNSPIDTracker is a no-op on non-Linux platforms.
type DNSPIDTracker struct{}

// Lookup always returns zero values on non-Linux.
func (*DNSPIDTracker) Lookup(_ uint64, _ uint16) (uint32, string, string, uint64) {
	return 0, "", "", 0
}

// LookupWithBinary always returns zero values on non-Linux.
func (*DNSPIDTracker) LookupWithBinary(_ uint64, _ uint16) (uint32, string, string, string, uint64) {
	return 0, "", "", "", 0
}

// BinaryPathForPID always returns empty on non-Linux.
func (*DNSPIDTracker) BinaryPathForPID(_ uint32) string { return "" }

// AddCgroup is a no-op on non-Linux.
func (*DNSPIDTracker) AddCgroup(_ string) (uint64, error) { return 0, nil }

// RemoveCgroup is a no-op on non-Linux.
func (*DNSPIDTracker) RemoveCgroup(_ uint64) {}

// Close is a no-op on non-Linux.
func (*DNSPIDTracker) Close() {}
