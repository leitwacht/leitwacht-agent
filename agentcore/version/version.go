// Package version exposes the build-time Version and Commit variables
// for binaries built under agentcore/.
//
// Set at link time via:
//
//	go build -ldflags "-X .../agentcore/version.Version=v1.2.3 \
//	                   -X .../agentcore/version.Commit=abcdef0"
package version

// Version is the agentcore-side build version, set at link time via -ldflags.
//
//nolint:gochecknoglobals // populated by the Go linker, not at runtime
var Version = "dev"

// Commit is the agentcore-side build commit SHA, set at link time via -ldflags.
//
//nolint:gochecknoglobals // populated by the Go linker, not at runtime
var Commit = "unknown"
