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
