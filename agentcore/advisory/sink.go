package advisory

import "context"

// Sink ships an advisory to its upstream destination. EE plugs in a
// gRPC adapter; CE will plug in stdout / Prometheus / webhook
// implementations. agentcore code never imports a concrete sink — it
// receives one through construction and calls ReportAdvisory on it.
//
// The method is named ReportAdvisory rather than Report so the
// reporter package's *Reporter (which already has a Report method
// for violations) can satisfy this interface during the Phase 1
// transition without an adapter wrapper.
//
// Error contract: implementations MAY return errors, but callers in
// agentcore are NOT required to act on them — the canonical
// behaviour is "log and forget". A failed advisory is never
// load-bearing: it's a hint for operators, not enforcement state.
// CE sinks (webhook, etc.) where errors are operationally meaningful
// should still log and persist locally rather than expecting the
// caller to retry or branch on the return value. The handler today
// discards the result via `_ =` — keep that pattern.
type Sink interface {
	ReportAdvisory(ctx context.Context, a *Advisory) error
}
