//go:build !linux

package enforcer

// StartCredwatch is a no-op on non-linux (BPF LSM requires Linux).
func (m *Manager) StartCredwatch() error { return nil }

// StopCredwatch is a no-op on non-linux.
func (m *Manager) StopCredwatch() {}

// CredwatchLSMLoaded always returns false on non-linux.
func (m *Manager) CredwatchLSMLoaded() bool { return false }

// AttachCredwatch is a no-op on non-linux.
func (m *Manager) AttachCredwatch(_, _ string, _, _ bool) {}

// DetachCredwatch is a no-op on non-linux.
func (m *Manager) DetachCredwatch(_ string) {}

// AttachCredwatchPaths is a no-op on non-linux.
func (m *Manager) AttachCredwatchPaths(_ string, _ []string, _, _ bool) {}
