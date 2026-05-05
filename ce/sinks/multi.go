// Package sinks contains the CE-side adapters that ship violations and
// advisories from agentcore to operator-facing destinations: NDJSON on
// stderr, a Prometheus registry, and an opt-in webhook. Each adapter
// satisfies both violation.Sink and advisory.Sink so callers can wire a
// single instance into the handler.
package sinks

import (
	"context"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/advisory"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/agentcore/violation"
)

// Multi fans a single Report/Advisory call out to multiple sinks in
// declared order. Sinks must be non-blocking — a slow sink delays every
// later sink in the slice for the same call.
type Multi struct {
	Violations []violation.Sink
	Advisories []advisory.Sink
}

// ReportAsync fans out a violation report.
func (m *Multi) ReportAsync(
	ctx context.Context,
	info enforcer.ContainerInfo,
	stats *enforcer.EgressStats,
	interim bool,
	bucketTS time.Time,
) {
	for _, s := range m.Violations {
		s.ReportAsync(ctx, info, stats, interim, bucketTS)
	}
}

// ReportAdvisory fans out an advisory and aggregates the first error.
func (m *Multi) ReportAdvisory(ctx context.Context, a *advisory.Advisory) error {
	var firstErr error
	for _, s := range m.Advisories {
		if err := s.ReportAdvisory(ctx, a); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
