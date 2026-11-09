package enforcer

import (
	"context"
	"net"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/wildcard"
)

// maxDNSSeedsPerSlot bounds the per-slot record of seeded names. The
// kernel map is an LRU of 8192 entries (one per ip:port); the record only
// serves carry-forward and pre-bind evaluation, so overflowing it just
// means an older entry is re-resolved after a policy change.
const maxDNSSeedsPerSlot = 8192

type dnsSeedKey struct {
	Name string
	IP   [4]byte
}

type dnsSeed struct {
	Ports []int
	Prio  uint32
}

// matchBuildFQDN returns the first rule matching name, with the same
// per-action wildcard semantics as the per-pod proxy (allow: single
// label; deny: any depth). rules are in priority order.
func matchBuildFQDN(name string, rules []BuildFQDNRule) (BuildFQDNRule, bool) {
	for _, r := range rules {
		if r.Allow {
			if wildcard.MatchesSingle(name, r.Pattern) {
				return r, true
			}

			continue
		}

		if wildcard.MatchesSuffix(name, r.Pattern) {
			return r, true
		}
	}

	return BuildFQDNRule{}, false
}

// BuildDNSDecision is the proxy's view of a RUN cgroup's policy binding.
type BuildDNSDecision struct {
	// Known is false while the cgroup has no entry yet (PENDING).
	Known bool
	State uint8
	Mode  uint8
	Key   PolicyKey
	// PolicyID is project@version/job ("" unless bound).
	PolicyID string
	// Rules are the bound policy's name rules (nil unless bound).
	Rules []BuildFQDNRule

	slot *slotState
}

// Enforcing reports whether name rules apply to this cgroup's queries:
// bound, and in shadow or enforce mode.
func (d BuildDNSDecision) Enforcing() bool {
	return d.Known && d.State == bkStateBound && d.slot != nil && d.Mode != bkModeAudit
}

func (b *BuildPolicyBinder) notifyLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// SetDNSProxyActive records whether the build DNS proxy is bound and the
// redirect on. Name rules are enforced only while it is; rows of cgroups
// whose policy has name rules are flagged fqdn_rules_inactive otherwise.
func (b *BuildPolicyBinder) SetDNSProxyActive(active bool) {
	if b.dnsActive.Swap(active) == active {
		return
	}

	b.dnsTimeMu.Lock()

	b.dnsTrans = append(b.dnsTrans, dnsTransition{at: time.Now(), active: active})
	if len(b.dnsTrans) > maxDNSTransitions {
		b.dnsTrans = b.dnsTrans[len(b.dnsTrans)-maxDNSTransitions:]
	}

	b.dnsTimeMu.Unlock()

	b.log.Info("buildkit build DNS proxy", "active", active)
}

// maxDNSTransitions bounds the proxy on/off history kept for rows.
const maxDNSTransitions = 256

type dnsTransition struct {
	at     time.Time
	active bool
}

// dnsActiveAt reports whether the proxy was active when a row was
// recorded (not when it is flushed): a row recorded while it was down
// stays flagged fqdn_rules_inactive after it comes back.
func (b *BuildPolicyBinder) dnsActiveAt(t time.Time) bool {
	b.dnsTimeMu.Lock()
	defer b.dnsTimeMu.Unlock()

	active := false

	for _, tr := range b.dnsTrans {
		if tr.at.After(t) {
			break
		}

		active = tr.active
	}

	return active
}

// DNSProxyActive reports SetDNSProxyActive's last value.
func (b *BuildPolicyBinder) DNSProxyActive() bool { return b.dnsActive.Load() }

// HoldEnabled reports whether the pre-bind hold is on, i.e. an enforce
// policy is in play. The DNS hold only delays answers then, so audit and
// shadow-only deployments never pay the latency.
func (b *BuildPolicyBinder) HoldEnabled() bool {
	b.holdMu.Lock()
	defer b.holdMu.Unlock()

	return b.holdOn
}

// DNSDecision returns the decision for a RUN cgroup (a live one only).
func (b *BuildPolicyBinder) DNSDecision(id uint64) BuildDNSDecision {
	b.mu.Lock()
	defer b.mu.Unlock()

	d, ok := b.cgs[id]
	if !ok {
		return BuildDNSDecision{}
	}

	out := BuildDNSDecision{Known: true, State: d.state, Mode: d.mode, Key: d.key}

	if d.state == bkStateBound && d.slot != nil {
		out.slot = d.slot
		out.PolicyID = d.policyID
		out.Rules = d.slot.policy.FQDNRules
		// d.mode is the cgroup's own (a mode-only flip keeps the slot).
	}

	return out
}

// DNSDecisionAt is DNSDecision for flush time: besides the live entry it
// finds one retired by a cgroup removal within the id-reuse grace of at
// (steps shorter than the flush interval are gone by then). Only the
// project, job and state are meaningful.
func (b *BuildPolicyBinder) DNSDecisionAt(id uint64, at time.Time) BuildDNSDecision {
	b.mu.Lock()
	defer b.mu.Unlock()

	d, ok := b.decisionFor(id, at)
	if !ok {
		return BuildDNSDecision{}
	}

	return BuildDNSDecision{Known: true, State: d.state, Mode: d.mode, Key: d.key}
}

// WaitDecision blocks until id has an entry (any state: ambiguous,
// unattributed and degraded end the wait too), the deadline passes, or ctx
// is done, and returns the decision (Known false on timeout). The DNS
// hold uses it to give the join time to bind a fresh RUN cgroup before its
// first name is answered.
func (b *BuildPolicyBinder) WaitDecision(ctx context.Context, id uint64, deadline time.Time) BuildDNSDecision {
	for {
		d := b.DNSDecision(id)
		if d.Known {
			return d
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return d
		}

		b.mu.Lock()
		ch := b.changed
		b.mu.Unlock()

		// Re-check: an entry may have been written between the lookup and
		// taking the channel.
		if d2 := b.DNSDecision(id); d2.Known {
			return d2
		}

		t := time.NewTimer(wait)

		select {
		case <-ch:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()

			return BuildDNSDecision{}
		}

		t.Stop()
	}
}

// SeedDNS seeds the slot's DNS-derived allow map for name's A answers,
// stamped with the matching allow rule's priority, and remembers them for
// carry-forward. It is a no-op when the decision is not enforcing.
func (b *BuildPolicyBinder) SeedDNS(dec BuildDNSDecision, name string, ips []net.IP, rule BuildFQDNRule) {
	if !dec.Enforcing() || !rule.Allow {
		return
	}

	ports := allowSeedPorts(rule.Ports, b.log)
	s := dec.slot

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}

		if err := b.dp.SeedDNS(s.idx, ip4, ports, rule.Prio); err != nil {
			b.log.Error("buildkit dns: seed allow map", "slot", s.idx, "error", err)

			continue
		}

		s.recordSeed(name, ip4, ports, rule.Prio)
	}
}

func (s *slotState) recordSeed(name string, ip4 net.IP, ports []int, prio uint32) {
	var k dnsSeedKey

	k.Name = name
	copy(k.IP[:], ip4)

	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()

	if s.dns == nil {
		s.dns = map[dnsSeedKey]dnsSeed{}
	}

	if _, ok := s.dns[k]; !ok && len(s.dns) >= maxDNSSeedsPerSlot {
		return
	}

	s.dns[k] = dnsSeed{Ports: ports, Prio: prio}
}

// dnsAllows reports whether a name rule seeded ip:port into the slot.
func (s *slotState) dnsAllows(ip string, port int) bool {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return false
	}

	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()

	for k, v := range s.dns {
		if string(k.IP[:]) != string(p) {
			continue
		}

		for _, vp := range v.Ports {
			if vp == port || vp == 0 {
				return true
			}
		}
	}

	return false
}

// carryDNSLocked copies the seeds of from that still match an allow rule
// of to's policy into to (re-prioritised, with the new rule's ports), so a
// policy update does not flush what the build already resolved. A name
// that now matches a deny rule, or no allow rule, is dropped. Called with
// b.mu held, before any cgroup is flipped onto to.
func (b *BuildPolicyBinder) carryDNSLocked(from, to *slotState) {
	if from == nil || to == nil || from == to {
		return
	}

	from.dnsMu.Lock()

	keys := make([]dnsSeedKey, 0, len(from.dns))
	for k := range from.dns {
		keys = append(keys, k)
	}

	from.dnsMu.Unlock()

	for _, k := range keys {
		rule, ok := matchBuildFQDN(k.Name, to.policy.FQDNRules)
		if !ok || !rule.Allow {
			continue
		}

		ip := net.IP(k.IP[:])
		ports := allowSeedPorts(rule.Ports, b.log)

		if err := b.dp.SeedDNS(to.idx, ip, ports, rule.Prio); err != nil {
			b.log.Debug("buildkit dns: carry-forward seed", "slot", to.idx, "error", err)

			return
		}

		to.recordSeed(k.Name, ip, ports, rule.Prio)
	}
}
