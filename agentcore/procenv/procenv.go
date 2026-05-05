// Package procenv reads environment variable NAMES (never values) for a
// running process from /proc/<pid>/environ. The point is to answer
// "what secrets could this process have exfiltrated?" without recording
// the secrets themselves: a violation report carrying
// `["AWS_ACCESS_KEY_ID", "GITLAB_TOKEN", "DATABASE_URL"]` tells the
// operator the blast radius without becoming the leak it warns about.
//
// Linux only. Other platforms get a stub that always returns nil — the
// agent itself is Linux-only at runtime, but build tags here keep
// macOS/Windows tests compilable.
//
// Race posture: best-effort. If the process exited between violation
// recording and the env read, we return nil without an error. Callers
// must accept that some violations will lack env names — better that
// than blocking the report path on /proc availability.
package procenv

// Names returns the slice of environment variable NAMES set on pid at
// the time of its most recent execve. Values are never read or
// returned. Returns nil if the process exited, /proc is unreadable,
// or the platform is non-Linux.
//
// The returned slice is sorted and deduplicated. Empty environments
// return an empty (non-nil) slice; nil signals "could not read."
func Names(pid int) []string {
	return namesLinux(pid)
}
