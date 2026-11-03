package enforcer

import (
	"bytes"
	"strings"
)

const (
	// maxResolvConfBytes caps how much of a container's resolv.conf is read.
	maxResolvConfBytes = 4096

	// maxSearchEntries mirrors glibc's historical search-list limit.
	maxSearchEntries = 6
)

// parseSearchList extracts the resolver search list from resolv.conf
// content; see parseResolvConf for the rules.
func parseSearchList(data []byte) []string {
	return parseResolvConf(data).search
}

// resolvConf is the part of a container's resolv.conf the agent cares about.
type resolvConf struct {
	// search is the normalised search list (see normalizeSearch).
	search []string
	// ndots is the effective "options ndots:N" value, clamped to
	// [0, maxNdots]; defaultNdots when not explicit.
	ndots int
	// ndotsExplicit is true when an options line set ndots.
	ndotsExplicit bool
	// readable is true when resolv.conf was read (an empty file is
	// readable; a missing or refused one is not). Set by the reader.
	readable bool
}

const (
	// defaultNdots is the resolver default when no ndots option is present.
	defaultNdots = 1
	// maxNdots is glibc's RES_MAXNDOTS clamp.
	maxNdots = 15
)

// parseResolvConf parses resolv.conf content. Only "search", "domain" and
// "options ndots:N" matter; as in glibc, the last occurrence of search or
// domain wins ("domain" yields a one-entry list) and the last ndots option
// wins (values above 15 clamp to 15; non-numeric values are ignored).
// Entries are lowercased with any trailing dot removed, and at most
// maxSearchEntries are kept. nameserver and other options are ignored.
// If data fills the read cap, a final unterminated line is discarded as
// possibly truncated.
func parseResolvConf(data []byte) resolvConf {
	rc := resolvConf{ndots: defaultNdots, readable: true}

	if len(data) >= maxResolvConfBytes {
		data = data[:maxResolvConfBytes]

		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i]
		} else {
			return rc // readable, but nothing trustworthy in it
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch strings.ToLower(fields[0]) {
		case "search":
			rc.search = normalizeSearch(fields[1:])
		case "domain":
			rc.search = normalizeSearch(fields[1:2])
		case "options":
			if n, ok := parseNdotsOption(fields[1:]); ok {
				rc.ndots, rc.ndotsExplicit = n, true
			}
		}
	}

	return rc
}

// parseNdotsOption returns the last valid ndots:N among the option tokens
// of one options line.
func parseNdotsOption(opts []string) (int, bool) {
	n, found := 0, false

	for _, o := range opts {
		if strings.HasPrefix(o, "#") || strings.HasPrefix(o, ";") {
			break // comment tail
		}

		v, ok := strings.CutPrefix(o, "ndots:")
		if !ok || v == "" {
			continue
		}

		val := 0

		for _, c := range v {
			if c < '0' || c > '9' {
				val = -1

				break
			}

			if val <= maxNdots { // saturate: huge values clamp, no overflow
				val = val*10 + int(c-'0')
			}
		}

		if val < 0 {
			continue
		}

		n, found = min(val, maxNdots), true
	}

	return n, found
}

func normalizeSearch(raw []string) []string {
	out := make([]string, 0, len(raw))

	for _, s := range raw {
		if strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			break // comment tail
		}

		s = strings.TrimSuffix(strings.ToLower(s), ".")
		if s == "" {
			continue
		}

		if len(out) == maxSearchEntries {
			break
		}

		out = append(out, s)
	}

	return out
}

// expansionPair is one way to read a query as a search-list expansion:
// qname == base + "." + suffix, with suffix taken from the search list.
type expansionPair struct {
	base, suffix string
}

// expansionPairs returns every (B, S) split of qname with S in list at a
// label boundary. Empty when qname is not a possible expansion.
func expansionPairs(qname string, list []string) []expansionPair {
	var pairs []expansionPair

	for _, s := range list {
		suffix := "." + s
		if len(qname) > len(suffix) && strings.HasSuffix(qname, suffix) {
			pairs = append(pairs, expansionPair{base: qname[:len(qname)-len(suffix)], suffix: s})
		}
	}

	return pairs
}

// expansionBases returns every candidate bare name B such that qname is
// B + "." + S for some S in the search list.
func expansionBases(qname string, list []string) []string {
	var bases []string

	for _, p := range expansionPairs(qname, list) {
		bases = append(bases, p.base)
	}

	return bases
}
