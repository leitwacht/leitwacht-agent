package enforcer

// ReservedDomains lists DNS names the per-pod DNS proxy
// answers itself, bypassing the configured policy rules. The proxy
// synthesises a response (typically the pinned attachment IP for
// `_leitwacht.attached.local`) without recording the query in DNS
// activity — these are agent-internal handshakes, not job egress.
//
// This list is the runtime authority. The backend's store package
// The Enterprise Edition backend keeps a hard-coded copy of this list
// used to suppress search-list derivatives from the anomaly filter;
// that copy MUST agree with this slice. The two are intentionally
// duplicated rather than shared because the backend never imports
// agentcore — keeping agentcore as a leaf module (no edges to control-
// plane code) is a hard architectural invariant.
//
// Entries are bare names (no trailing dot). Match callers strip
// trailing dots and lowercase before comparing.
//
// To add a name, also confirm:
//   - HandleDNSQuery short-circuits it (dnsproxy.go).
//   - The init container that needs it uses the trailing-dot form so
//     resolver search-list expansion is bypassed.
//   - The store's reservedDomains slice is updated in lockstep.
//
//nolint:gochecknoglobals // package-level immutable constant, expressed as a slice for iteration
var ReservedDomains = []string{
	"_leitwacht.attached.local",
}
