//go:build !linux

package enforcer

// Start is a no-op on non-linux (BPF LSM requires Linux).
func (m *Manager) Start() error { return nil }

// Stop is a no-op on non-linux.
func (m *Manager) Stop() {}

// LSMLoaded always returns false on non-linux.
func (m *Manager) LSMLoaded() bool { return false }

// AttachHoneypot is a no-op on non-linux.
func (m *Manager) AttachHoneypot(_, _ string) {}

// DetachHoneypot is a no-op on non-linux.
func (m *Manager) DetachHoneypot(_ string) {}
