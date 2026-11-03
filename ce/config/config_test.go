package config

import "testing"

func TestLoadCanonicalisesActionEnums(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"mixed case", "Block", "block"},
		{"padded upper", " BLOCK ", "block"},
		{"lower audit", "audit", "audit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")
			t.Setenv("LEITWACHT_CE_DEFAULT_ACTION", tc.in)
			t.Setenv("LEITWACHT_CE_UNKNOWN_PROJECT", " Pass ")

			c, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			if c.DefaultAction != tc.want {
				t.Errorf("DefaultAction = %q, want %q", c.DefaultAction, tc.want)
			}

			if c.UnknownProjectMode != "pass" {
				t.Errorf("UnknownProjectMode = %q, want pass", c.UnknownProjectMode)
			}
		})
	}
}

func TestLoadDNSExpansionSuppression(t *testing.T) {
	t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")

	c, err := Load()
	if err != nil || c.DNSExpansionSuppression != "structural" {
		t.Fatalf("default = %q, err %v; want structural", c.DNSExpansionSuppression, err)
	}

	t.Setenv("LEITWACHT_CE_DNS_EXPANSION_SUPPRESSION", "off")

	if c, err = Load(); err != nil || c.DNSExpansionSuppression != "off" {
		t.Fatalf("off = %q, err %v", c.DNSExpansionSuppression, err)
	}

	t.Setenv("LEITWACHT_CE_DNS_EXPANSION_SUPPRESSION", "sometimes")

	if _, err = Load(); err == nil {
		t.Fatal("invalid value must be rejected")
	}
}

func TestLoadClusterDomain(t *testing.T) {
	t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")

	c, err := Load()
	if err != nil || c.ClusterDomain != "cluster.local" {
		t.Fatalf("default = %q, err %v", c.ClusterDomain, err)
	}

	t.Setenv("LEITWACHT_CE_CLUSTER_DOMAIN", "k8s.example")

	if c, err = Load(); err != nil || c.ClusterDomain != "k8s.example" {
		t.Fatalf("custom = %q, err %v", c.ClusterDomain, err)
	}

	t.Setenv("LEITWACHT_CE_CLUSTER_DOMAIN", " K8s.Example. ")

	if c, err = Load(); err != nil || c.ClusterDomain != "k8s.example" {
		t.Fatalf("normalised = %q, err %v", c.ClusterDomain, err)
	}

	t.Setenv("LEITWACHT_CE_CLUSTER_DOMAIN", "bad_domain..x")

	if _, err = Load(); err == nil {
		t.Fatal("invalid cluster domain must be rejected at startup")
	}
}

func TestLoadDNSCacheSize(t *testing.T) {
	t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")

	c, err := Load()
	if err != nil || c.DNSCacheSize != 1024 {
		t.Fatalf("default = %d, err %v; want 1024", c.DNSCacheSize, err)
	}

	t.Setenv("LEITWACHT_CE_DNS_CACHE_SIZE", "0")

	if c, err = Load(); err != nil || c.DNSCacheSize != 0 {
		t.Fatalf("0 = %d, err %v; want disabled", c.DNSCacheSize, err)
	}

	t.Setenv("LEITWACHT_CE_DNS_CACHE_SIZE", "-1")

	if _, err = Load(); err == nil {
		t.Fatal("negative size must be rejected")
	}

	t.Setenv("LEITWACHT_CE_DNS_CACHE_SIZE", "lots")

	if _, err = Load(); err == nil {
		t.Fatal("non-numeric size must be rejected")
	}
}
