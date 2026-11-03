//go:build !linux

package enforcer

// readSearchList is Linux-only; elsewhere no search list is known and no
// expansion is ever suppressed.
func readSearchList(string, int) []string { return nil }
