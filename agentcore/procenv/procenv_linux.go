//go:build linux

package procenv

import (
	"bytes"
	"fmt"
	"os"
	"sort"
)

// maxEnvironBytes caps how much we'll read from /proc/<pid>/environ.
// The kernel's MAX_ARG_STRLEN is 32 pages (128KiB on 4K page systems);
// MAX_ARG_STRINGS is 0x7FFFFFFF. In practice CI job environments are
// tens of KiB. 256KiB is a generous ceiling that protects against a
// pathological attacker stuffing the environ to OOM the agent.
const maxEnvironBytes = 256 * 1024

func namesLinux(pid int) []string {
	if pid <= 0 {
		return nil
	}

	path := fmt.Sprintf("/proc/%d/environ", pid)

	f, err := os.Open(path)
	if err != nil {
		// ENOENT: process exited. EACCES: file mode 0400 and we're not
		// root (shouldn't happen in DaemonSet, but tolerated). Either
		// way the caller gets nil, the report ships without env names.
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only, nothing to flush

	// LimitReader to keep a hostile environ bounded. We read into one
	// buffer rather than streaming because environ entries are NUL-
	// separated and crossing a read boundary mid-name complicates the
	// scanner without buying much.
	buf := make([]byte, 0, 8*1024)
	chunk := make([]byte, 8*1024)

	for len(buf) < maxEnvironBytes {
		n, readErr := f.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}

		if readErr != nil {
			break
		}
	}

	return extractNames(buf)
}

// extractNames parses a NUL-separated `KEY=VALUE\0KEY=VALUE\0…` blob
// and returns just the KEYs. Values are never copied off the input
// buffer — we only retain references to the byte ranges before each
// `=`. The returned slice is sorted and deduplicated.
//
// Malformed entries (no `=`, empty key) are skipped silently. /proc/
// <pid>/environ may have a trailing NUL or stray bytes from the kernel
// snapshot; the scanner is tolerant.
func extractNames(buf []byte) []string {
	if len(buf) == 0 {
		return []string{}
	}

	// Trim trailing NULs so the final Split entry isn't an empty
	// "KEY=VALUE" with no separator.
	buf = bytes.TrimRight(buf, "\x00")
	if len(buf) == 0 {
		return []string{}
	}

	parts := bytes.Split(buf, []byte{0})

	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		eq := bytes.IndexByte(p, '=')
		if eq <= 0 {
			// No `=` (skip) or starts with `=` (empty key, skip).
			continue
		}

		name := string(p[:eq])
		if _, dup := seen[name]; dup {
			continue
		}

		seen[name] = struct{}{}
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}
