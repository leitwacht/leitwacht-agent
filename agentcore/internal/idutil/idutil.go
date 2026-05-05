// Package idutil holds id-handling helpers shared across agentcore.
// Internal so external consumers don't grow incidental dependencies on
// the exact truncation length.
package idutil

// shortIDLen is the number of characters to show when truncating
// container IDs in logs. Matches Docker's short-id convention so log
// lines line up with `docker ps` output.
const shortIDLen = 12

// Trunc truncates a container ID for logging. Shorter strings pass
// through unchanged.
func Trunc(id string) string {
	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}

	return id
}
