package config

import (
	"strings"
	"testing"
)

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

func TestLoadCredwatchPathClasses(t *testing.T) {
	t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.CredwatchReportOnly != "/.docker/config.json,/.npmrc,/.netrc,/.pypirc" {
		t.Errorf("report-only default = %q", c.CredwatchReportOnly)
	}

	if c.CredwatchExclude != "" {
		t.Errorf("exclude default = %q, want empty", c.CredwatchExclude)
	}

	for _, ro := range strings.Split(c.CredwatchReportOnly, ",") {
		for _, w := range strings.Split(c.CredwatchPaths, ",") {
			if ro == w {
				t.Errorf("%q is both watched and report-only by default", ro)
			}
		}
	}

	if !strings.Contains(c.CredwatchPaths, "/.aws/credentials") {
		t.Error("high-value paths must stay watched")
	}

	t.Setenv("LEITWACHT_CE_CREDWATCH_REPORT_ONLY_PATHS", "/.foo/bar")

	if c, err = Load(); err != nil || c.CredwatchReportOnly != "/.foo/bar" {
		t.Fatalf("override = %q, err %v", c.CredwatchReportOnly, err)
	}

	t.Setenv("LEITWACHT_CE_CREDWATCH_REPORT_ONLY_PATHS", "")

	if c, err = Load(); err != nil || c.CredwatchReportOnly != "" {
		t.Fatalf("explicit empty must disable the class, got %q err %v", c.CredwatchReportOnly, err)
	}
}

func TestLoadBuildkitEnforcement(t *testing.T) {
	t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")

	c, err := Load()
	if err != nil || c.BuildkitEnforcement != "audit" || c.BuildkitKillOnUnattributed {
		t.Fatalf("defaults = %q kill=%v, err %v; want audit, no kill", c.BuildkitEnforcement, c.BuildkitKillOnUnattributed, err)
	}

	t.Setenv("LEITWACHT_CE_BUILDKIT_ENFORCEMENT", " Shadow ")
	t.Setenv("LEITWACHT_CE_BUILDKIT_KILL_ON_UNATTRIBUTED", "true")

	if c, err = Load(); err != nil || c.BuildkitEnforcement != "shadow" || !c.BuildkitKillOnUnattributed {
		t.Fatalf("shadow = %q kill=%v, err %v", c.BuildkitEnforcement, c.BuildkitKillOnUnattributed, err)
	}

	t.Setenv("LEITWACHT_CE_BUILDKIT_ENFORCEMENT", "block")

	if _, err = Load(); err == nil || !strings.Contains(err.Error(), "audit|shadow|enforce") {
		t.Fatalf("invalid mode accepted: %v", err)
	}
}

func TestLoadBuildkitDNSProxy(t *testing.T) {
	t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")

	c, err := Load()
	if err != nil || c.BuildkitDNSProxy || c.BuildkitDNSProc != "buildkitd" || c.BuildkitDNSListen != "127.0.0.153:15354" {
		t.Fatalf("defaults = %v %q %q, err %v; want off, buildkitd, 127.0.0.153:15354",
			c.BuildkitDNSProxy, c.BuildkitDNSProc, c.BuildkitDNSListen, err)
	}

	t.Setenv("LEITWACHT_CE_BUILDKIT_DNS_PROXY", "true")
	t.Setenv("LEITWACHT_CE_BUILDKIT_DNS_PROC", "bk")
	t.Setenv("LEITWACHT_CE_BUILDKIT_DNS_LISTEN", "127.0.0.9:5300")

	if c, err = Load(); err != nil || !c.BuildkitDNSProxy || c.BuildkitDNSProc != "bk" || c.BuildkitDNSListen != "127.0.0.9:5300" {
		t.Fatalf("set = %v %q %q, err %v", c.BuildkitDNSProxy, c.BuildkitDNSProc, c.BuildkitDNSListen, err)
	}
}

func TestLoadBuildkitTLSValidation(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		env     map[string]string
		wantErr string
	}{
		{"tcp + tls ok", "tcp://bk:1234", map[string]string{"LEITWACHT_CE_BUILDKIT_TLS_CA": "/ca"}, ""},
		{"unix:// + tls", "unix:///run/bk.sock", map[string]string{"LEITWACHT_CE_BUILDKIT_TLS_CA": "/ca"}, "unix"},
		{"unix:/path + tls", "unix:/run/bk.sock", map[string]string{"LEITWACHT_CE_BUILDKIT_TLS_SERVER_NAME": "x"}, "unix"},
		{"unix without tls ok", "unix:///run/bk.sock", nil, ""},
		{"cert without key", "tcp://bk:1234", map[string]string{"LEITWACHT_CE_BUILDKIT_TLS_CERT": "/c"}, "together"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LEITWACHT_CE_DNS_UPSTREAM", "10.0.0.2:53")
			t.Setenv("LEITWACHT_CE_BUILDKIT_GRPC_ADDR", tc.addr)

			for _, k := range []string{
				"LEITWACHT_CE_BUILDKIT_TLS_CA", "LEITWACHT_CE_BUILDKIT_TLS_CERT",
				"LEITWACHT_CE_BUILDKIT_TLS_KEY", "LEITWACHT_CE_BUILDKIT_TLS_SERVER_NAME",
			} {
				t.Setenv(k, "")
			}

			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			_, err := Load()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
