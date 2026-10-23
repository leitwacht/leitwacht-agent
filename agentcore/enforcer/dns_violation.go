package enforcer

// handleDNSViolation is the DNSProxyConfig.OnDNSViolation hook for one
// netns context. It resolves which container the offending query came from,
// de-duplicates, and invokes the callback registered via SetOnDNSViolation
// asynchronously so a slow kill never stalls the DNS handler.
//
// Containers that cannot be identified are skipped: acting on an empty or
// guessed ID would kill, report on, or detach the wrong thing.
func (m *Manager) handleDNSViolation(nctx *NetnsContext, cgroupID uint64, domain, action string) {
	m.mu.Lock()
	fn := m.onDNSViolation
	m.mu.Unlock()

	if fn == nil {
		return
	}

	containerID, resolvedCgroup := m.resolveDNSViolator(nctx, cgroupID)
	if containerID == "" {
		m.logger.Debug("dns violation: container unresolved, no action", "action", action)

		return
	}

	m.mu.Lock()
	if m.dnsViolationSeen == nil {
		m.dnsViolationSeen = make(map[string]struct{})
	}

	// Forget containers that are gone so the set stays bounded.
	for id := range m.dnsViolationSeen {
		if _, live := m.enforcers[id]; !live {
			delete(m.dnsViolationSeen, id)
		}
	}

	_, dup := m.dnsViolationSeen[containerID]
	m.dnsViolationSeen[containerID] = struct{}{}
	m.mu.Unlock()

	if dup {
		return
	}

	go fn(resolvedCgroup, domain, action)
}

// resolveDNSViolator maps the cgroup the DNS PID tracker attributed a query
// to onto a container in nctx. The returned cgroup ID is one that
// ContainerIDForCgroup resolves back to the same container.
//
// If the tracker missed (cgroupID 0, e.g. a short-lived process) and the
// netns holds exactly one container, that container is the only possible
// source. With several siblings the source is ambiguous, so nothing is
// returned.
func (m *Manager) resolveDNSViolator(nctx *NetnsContext, cgroupID uint64) (string, uint64) {
	if cgroupID != 0 {
		m.mu.Lock()
		id := m.containerIDFromEnforcersLocked(cgroupID)
		m.mu.Unlock()

		if id != "" {
			return id, cgroupID
		}
	}

	nctx.mu.RLock()

	var only string

	if len(nctx.pids) == 1 {
		for id := range nctx.pids {
			only = id
		}
	}

	nctx.mu.RUnlock()

	if only == "" {
		return "", 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	e := m.enforcers[only]
	if e == nil {
		return "", 0
	}

	return only, e.cgroupID
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
