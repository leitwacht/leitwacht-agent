package policy

// Source yields a project's resolved policy. Implementations
// adapt from whatever upstream produces rules: gRPC stream + rendered
// store (EE), YAML file (CE), or in-memory test fixtures.
//
// Resolve returns (pol, true, nil) on hit, (nil, false, nil) on miss,
// and (nil, false, err) on a recoverable conversion failure the caller
// should log but not treat as fatal. The boolean is the only way the
// cache distinguishes a miss from a malformed-but-present row.
type Source interface {
	Resolve(projectPath string) (*ResolvedPolicy, bool, error)
}

// WatcherReadiness reports whether the agent-side rule watcher has
// completed at least one snapshot phase. Until Ready() returns true
// the cache does not trust the rulestore and falls through to the
// legacy unary GetPolicy RPC.
type WatcherReadiness interface {
	Ready() bool
}
