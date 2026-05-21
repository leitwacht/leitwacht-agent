//go:build !linux

package enforcer

// StartProcMem is a no-op on non-linux (BPF LSM requires Linux).
func (m *Manager) StartProcMem() error { return nil }

// StopProcMem is a no-op on non-linux.
func (m *Manager) StopProcMem() {}

// ProcMemLSMLoaded always returns false on non-linux.
func (m *Manager) ProcMemLSMLoaded() bool { return false }

// AttachProcMem is a no-op on non-linux.
func (m *Manager) AttachProcMem(_, _ string, _ bool) {}

// DetachProcMem is a no-op on non-linux.
func (m *Manager) DetachProcMem(_ string) {}
