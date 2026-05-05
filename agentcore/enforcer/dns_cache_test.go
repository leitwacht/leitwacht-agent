package enforcer

import "testing"

const testDNSCacheDomain = "example.com"

func TestDNSCache_NilSafe(t *testing.T) {
	var c *DNSCache

	c.Record(testDNSCacheDomain, []string{"1.2.3.4"})

	if got := c.Lookup("1.2.3.4"); got != "" {
		t.Errorf("nil Lookup returned %q, want empty", got)
	}

	if got := c.Len(); got != 0 {
		t.Errorf("nil Len = %d, want 0", got)
	}
}

func TestDNSCache_RecordAndLookup(t *testing.T) {
	c := NewDNSCache()

	c.Record(testDNSCacheDomain, []string{"1.2.3.4", "5.6.7.8"})
	c.Record("other.com", []string{"9.9.9.9"})

	if got := c.Lookup("1.2.3.4"); got != testDNSCacheDomain {
		t.Errorf("1.2.3.4 → %q, want example.com", got)
	}

	if got := c.Lookup("5.6.7.8"); got != testDNSCacheDomain {
		t.Errorf("5.6.7.8 → %q, want example.com", got)
	}

	if got := c.Lookup("9.9.9.9"); got != "other.com" {
		t.Errorf("9.9.9.9 → %q, want other.com", got)
	}

	if got := c.Lookup("unknown"); got != "" {
		t.Errorf("unknown → %q, want empty", got)
	}
}

// Last-write-wins matches server-side BuildDNSReverseMap semantics. This
// keeps agent-side and (legacy) server-side attribution behaviour
// consistent when an IP legitimately serves multiple domains.
func TestDNSCache_LastWriteWins(t *testing.T) {
	c := NewDNSCache()

	c.Record("first.com", []string{"1.2.3.4"})
	c.Record("second.com", []string{"1.2.3.4"})

	if got := c.Lookup("1.2.3.4"); got != "second.com" {
		t.Errorf("1.2.3.4 → %q, want second.com (last-write-wins)", got)
	}
}

func TestDNSCache_EmptyInputsIgnored(t *testing.T) {
	c := NewDNSCache()

	c.Record("", []string{"1.2.3.4"})
	c.Record(testDNSCacheDomain, nil)
	c.Record(testDNSCacheDomain, []string{""})

	if got := c.Len(); got != 0 {
		t.Errorf("Len = %d, want 0 (empty inputs should be ignored)", got)
	}
}
