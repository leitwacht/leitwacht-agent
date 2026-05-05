// Package violation defines the interface the agent core uses to ship
// per-container egress results to whatever upstream the edition wires
// up — gRPC reports on EE, NDJSON / Prometheus / webhook on CE.
//
// The package intentionally re-uses the agentcore-side plain Go types
// (`enforcer.ContainerInfo`, `enforcer.EgressStats`) on the Sink
// surface rather than introducing wire-format mirrors. EE's gRPC
// adapter already does the plain → `agentpb.ViolationReport`
// conversion inside the reporter, and CE's adapters render the same
// plain values to their own formats — no third Go shape is needed.
//
// The Sink ships an entire container's lifetime egress in one call,
// not one Violation per call. The handler enforces this granularity
// (one report at detach plus periodic bucket flushes) and the wire
// formats EE / CE adapters produce mirror it.
package violation

import (
	"context"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

// Sink ships a container's egress result. ReportAsync is fire-and-
// forget: implementations may persist + send concurrently, return
// immediately, and surface delivery failures through their own
// logging or retry queue. The handler does not branch on errors.
//
// `interim` is true for periodic bucket flushes mid-container; false
// for the final detach-time send. `bucketTS` is the bucket window's
// start time (zero for non-bucketed legacy reports).
type Sink interface {
	ReportAsync(
		ctx context.Context,
		info enforcer.ContainerInfo,
		stats *enforcer.EgressStats,
		interim bool,
		bucketTS time.Time,
	)
}
