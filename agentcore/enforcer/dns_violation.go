package enforcer

// maxDNSViolationAttempts bounds how often a failing violation callback
// (e.g. a kill that errored) is retried for one container.
const maxDNSViolationAttempts = 3

// handleDNSViolation is the DNSProxyConfig.OnDNSViolation hook for one
// netns context. It resolves which container the offending query came from
// and invokes the callback registered via SetOnDNSViolation asynchronously,
// so a slow kill never stalls the DNS handler, at most once per container
// (retrying only after a failure, up to maxDNSViolationAttempts).
//
// There is deliberately no "only container in the netns" fallback: when the
// PID tracker misses (cgroup 0) or reports a cgroup that is not a known
// container, acting would mean guessing. In block mode the query has already
// been sinkholed, so skipping loses no containment, only the kill.
func (m *Manager) handleDNSViolation(_ *NetnsContext, cgroupID uint64, domain, action string) {
	if cgroupID == 0 {
		m.logger.Debug("dns violation: no cgroup attribution, no action", "action", action)

		return
	}

	m.mu.Lock()
	fn := m.onDNSViolation
	containerID := m.containerIDFromEnforcersLocked(cgroupID)

	if fn == nil || containerID == "" {
		m.mu.Unlock()

		if fn != nil {
			m.logger.Debug("dns violation: container unresolved, no action", "action", action)
		}

		return
	}

	if m.dnsViolationState == nil {
		m.dnsViolationState = make(map[string]int)
	}

	attempts := m.dnsViolationState[containerID]
	if attempts < 0 || attempts >= maxDNSViolationAttempts {
		m.mu.Unlock()

		return
	}

	m.dnsViolationState[containerID] = -1 // in flight / done
	m.mu.Unlock()

	go func() {
		err := fn(containerID, domain, action)
		if err == nil {
			return
		}

		m.logger.Warn("dns violation handler failed", "container_id", shortID(containerID), "error", err)

		m.mu.Lock()
		if _, live := m.dnsViolationState[containerID]; live {
			m.dnsViolationState[containerID] = attempts + 1
		}
		m.mu.Unlock()
	}()
}

// containerIDFromEnforcersLocked finds the attached container whose
// recorded cgroup IDs (attach point, or any leaf registered alongside it)
// include cgroupID. Caller holds m.mu.
func (m *Manager) containerIDFromEnforcersLocked(cgroupID uint64) string {
	for id, e := range m.enforcers {
		if e == nil {
			continue
		}

		if e.cgroupID == cgroupID {
			return id
		}

		for _, c := range e.dnsPIDCgroupIDs {
			if c == cgroupID {
				return id
			}
		}

		for _, c := range e.sockAttrCgroupIDs {
			if c == cgroupID {
				return id
			}
		}
	}

	return ""
}
