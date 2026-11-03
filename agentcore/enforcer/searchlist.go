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
// content. Only "search" and "domain" directives matter; as in glibc, the
// last occurrence of either wins ("domain" yields a one-entry list).
// Entries are lowercased with any trailing dot removed, and at most
// maxSearchEntries are kept. ndots/options/nameserver lines are ignored.
// If data fills the read cap, a final unterminated line is discarded as
// possibly truncated.
func parseSearchList(data []byte) []string {
	if len(data) >= maxResolvConfBytes {
		data = data[:maxResolvConfBytes]

		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i]
		} else {
			return nil
		}
	}

	var list []string

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch strings.ToLower(fields[0]) {
		case "search":
			list = normalizeSearch(fields[1:])
		case "domain":
			list = normalizeSearch(fields[1:2])
		}
	}

	return list
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
