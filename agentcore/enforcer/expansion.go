package enforcer

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	// ExpansionSuppressionStructural (the default) drops the event for
	// search-list expansions of public-looking domains under the cluster
	// domain that the cluster DNS confirms do not exist.
	ExpansionSuppressionStructural = "structural"

	// ExpansionSuppressionOff disables the classification entirely.
	ExpansionSuppressionOff = "off"
)

// publicLookingDomain reports whether b is a registrable-looking public
// domain: at least two labels, and its effective TLD is a Public Suffix List
// entry (ICANN or private, so e.g. *.appspot.com counts) rather than the
// list's implicit "any last label" default. b must itself sit below its
// public suffix (b == "co.uk" is not a domain). Single labels (redis) and
// internal-looking names (web-0.db, svc.ns, foo.local) are not public.
//
// Matching is on the lowercase ASCII (punycode) form, as it appears on the
// wire; a raw non-ASCII label never matches, which fails toward "not noise".
func publicLookingDomain(b string) bool {
	b = strings.TrimSuffix(strings.ToLower(b), ".")
	if !strings.Contains(b, ".") {
		return false
	}

	suffix, icann := publicsuffix.PublicSuffix(b)
	if !icann && !strings.Contains(suffix, ".") {
		return false // unlisted TLD: the PSL's default rule, not a real entry
	}

	_, err := publicsuffix.EffectiveTLDPlusOne(b)

	return err == nil
}

// DefaultClusterDomain is the Kubernetes cluster domain assumed when none
// is configured.
const DefaultClusterDomain = "cluster.local"

// expansionClass is the structural class of a query.
type expansionClass int

const (
	// expNone: not a public-looking search-list expansion.
	expNone expansionClass = iota
	// expCluster: a public-looking base under the cluster domain; the
	// cluster DNS answers it authoritatively, so it may be confirmed noise.
	expCluster
	// expOutside: a public-looking base under a suffix OUTSIDE the cluster
	// domain (a node search suffix, or one injected into the resolv.conf).
	// Never forwarded for classification.
	expOutside
)

// underDomain reports whether s equals domain or is a subdomain of it.
func underDomain(s, domain string) bool {
	return s == domain || strings.HasSuffix(s, "."+domain)
}

// classifyExpansion classifies qname against the container's search list.
// clusterDomain must already be normalised (clusterdomain.Normalize; empty
// means the default). It is configuration, never derived from the list: a job
// that can edit the shared resolv.conf must not be able to declare its own
// suffix "in-cluster". If any public-looking split uses a suffix outside the
// cluster domain the whole query is expOutside (the stricter class).
func classifyExpansion(qname string, list []string, clusterDomain string) expansionClass {
	if clusterDomain == "" {
		clusterDomain = DefaultClusterDomain
	}

	class := expNone

	for _, p := range expansionPairs(qname, list) {
		if !publicLookingDomain(p.base) {
			continue
		}

		if !underDomain(p.suffix, clusterDomain) {
			return expOutside
		}

		class = expCluster
	}

	return class
}

// isResolverNoise reports whether qname is a public-looking expansion at
// all (either class); kept for the structural tests.
func isResolverNoise(qname string, list []string) bool {
	return classifyExpansion(qname, list, DefaultClusterDomain) != expNone
}

// expansionClassFor classifies qname for the container owning cgroupID.
func (cfg *DNSProxyConfig) expansionClassFor(cgroupID uint64, qname string) expansionClass {
	if cfg.ExpansionSuppression == ExpansionSuppressionOff || cfg.SearchListFor == nil {
		return expNone
	}

	return classifyExpansion(qname, cfg.SearchListFor(cgroupID), cfg.ClusterDomain)
}
