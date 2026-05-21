package enforcer

// StartDNSPIDTracker loads the DNS PID attribution kprobe.
// Tolerant: logs a warning on failure and returns nil (process attribution
// degrades gracefully — DNS violations still fire, just without PID info).
func (m *Manager) StartDNSPIDTracker() error {
	tracker, err := NewDNSPIDTracker(m.logger)
	if err != nil {
		m.logger.Warn("dns pid tracker unavailable, process attribution disabled", "error", err)

		return nil
	}

	m.dnsPIDTracker = tracker
	m.logger.Info("dns pid tracker loaded")

	return nil
}

// StopDNSPIDTracker closes the DNS PID attribution kprobe.
func (m *Manager) StopDNSPIDTracker() {
	if m.dnsPIDTracker != nil {
		m.dnsPIDTracker.Close()
		m.dnsPIDTracker = nil
		m.logger.Info("dns pid tracker stopped")
	}
}
