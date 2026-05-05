package policy

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoPolicy is returned by a Provider when no policy exists for the
// requested projectPath and no fallback is available.
//
// IMPORTANT: the handler does NOT treat this as "skip enforcement."
// On any GetPolicy error (including ErrNoPolicy) the handler synthesises
// a policy carrying the daemon's DefaultAction and runs the full
// enforcement gauntlet. Whether that policy is treated as Enrolled or
// not depends on UnknownProjectMode (see handler.UnknownProjectMode).
// Callers wiring a custom Provider should preserve this contract — if
// you want CE-style "out of scope, leave it alone" behaviour for some
// project, return a *ResolvedPolicy with Enrolled=false rather than
// ErrNoPolicy, OR rely on the handler.UnknownPass mode to do the same.
var ErrNoPolicy = errors.New("no policy available")

// Provider yields a project's resolved policy to the handler. The
// handler treats any error as fail-open: it constructs a default-action
// ResolvedPolicy and continues. Implementations:
//
//   - Resolver (this package): direct Source lookup, no caching.
//     Used by CE where the YAML loader is fully synchronous.
//   - ee/policycache.Cache: Source-first with BBolt persistence and
//     gRPC fallback. Used by EE.
type Provider interface {
	GetPolicy(ctx context.Context, projectPath string) (*ResolvedPolicy, error)
}

// Resolver is a no-cache Provider that delegates straight to a Source.
// Suitable when the Source is fast and synchronous (e.g., an in-memory
// YAML snapshot). The handler's existing fail-open path covers the
// before-Ready window without needing a stale-cache layer here.
type Resolver struct {
	source    Source
	readiness WatcherReadiness
}

// NewResolver returns a Provider that consults src for every call.
// Both src and readiness are required: until readiness.Ready() returns
// true, GetPolicy returns ErrNoPolicy so the handler fails open with
// its default action rather than serving from a half-loaded snapshot.
func NewResolver(src Source, readiness WatcherReadiness) *Resolver {
	return &Resolver{source: src, readiness: readiness}
}

// GetPolicy returns the policy for projectPath. Returns ErrNoPolicy on
// miss or before the source is ready; the caller is expected to handle
// that as fail-open.
func (r *Resolver) GetPolicy(_ context.Context, projectPath string) (*ResolvedPolicy, error) {
	if !r.readiness.Ready() {
		return nil, fmt.Errorf("%w: source not ready", ErrNoPolicy)
	}

	pol, ok, err := r.source.Resolve(projectPath)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", projectPath, err)
	}

	if !ok {
		return nil, fmt.Errorf("%w for %s", ErrNoPolicy, projectPath)
	}

	return pol, nil
}
