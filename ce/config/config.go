// Package config loads CE daemon configuration from environment
// variables. CE is intentionally backend-free, so the config has no
// gRPC/auth fields — RULES_PATH is the source of truth and the agent
// is otherwise self-contained.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved CE daemon settings.
type Config struct {
	// Rule source.
	RulesPath string

	// Container runtime + scope mapping.
	ContainerRuntime   string // "docker" or "containerd"
	ContainerSocket    string
	ContainerdNS       string
	RunnerPodNamespace string // K8S namespace filter, comma-separated
	ScopeLabel         string // container label whose value selects a scope
	ScopeEnv           string // container env var whose value selects a scope (fallback)

	// Enforcement defaults.
	DefaultAction      string // "block" | "audit" | "allow" — fallback when no scope matches
	UnknownProjectMode string // "enforce" (default — apply DefaultAction) | "pass" (passive-only, no checks)
	DNSUpstream        string
	TrustedCIDRs       string
	HoneypotEnabled    bool
	HoneypotDir        string
	RecordEnvNames     bool // when true, attach env-var NAMES (never values) to each Violation report
	MaxConcurrentEnf   int
	EventBuffer        int           // size of the watcher's event channel; back-pressures containerd subscriptions when full
	NetnsGrace         time.Duration // how long a netns context survives after its last container detaches
	BucketInterval     time.Duration

	// Sinks.
	StdoutEnabled  bool
	PromEnabled    bool
	PromAddr       string // ":9090"
	WebhookURL     string
	WebhookAuth    string // "Bearer ..." passed verbatim if non-empty
	WebhookTimeout time.Duration

	// Logging.
	LogLevel string
}

// Load reads environment variables with the LEITWACHT_CE_ prefix and
// returns a populated Config. Missing optional values fall back to the
// defaults documented in ce/SCHEMA.md.
func Load() (*Config, error) {
	c := &Config{
		RulesPath:          envOr("LEITWACHT_CE_RULES_PATH", "/etc/leitwacht/rules.yaml"),
		ContainerRuntime:   envOr("LEITWACHT_CE_CONTAINER_RUNTIME", "containerd"),
		ContainerSocket:    os.Getenv("LEITWACHT_CE_CONTAINER_SOCKET"),
		ContainerdNS:       envOr("LEITWACHT_CE_CONTAINERD_NS", "k8s.io"),
		RunnerPodNamespace: os.Getenv("LEITWACHT_CE_RUNNER_POD_NAMESPACE"),
		ScopeLabel:         envOr("LEITWACHT_CE_SCOPE_LABEL", "leitwacht.eu/scope"),
		ScopeEnv:           envOr("LEITWACHT_CE_SCOPE_ENV", "LEITWACHT_SCOPE"),
		DefaultAction:      envOr("LEITWACHT_CE_DEFAULT_ACTION", "block"),
		UnknownProjectMode: envOr("LEITWACHT_CE_UNKNOWN_PROJECT", "enforce"),
		// DNSUpstream is intentionally required: defaulting to public
		// resolvers (1.1.1.1, 8.8.8.8) would leak every CI job's DNS
		// queries to a third party and bypass cluster-internal DNS
		// (e.g., kube-dns / CoreDNS for *.svc.cluster.local). Operators
		// must point this at their own resolver — typically the kube-
		// dns ClusterIP on K8s or the host's recursive resolver on
		// bare metal.
		DNSUpstream:     os.Getenv("LEITWACHT_CE_DNS_UPSTREAM"),
		TrustedCIDRs:    os.Getenv("LEITWACHT_CE_TRUSTED_CIDRS"),
		HoneypotEnabled: envBool("LEITWACHT_CE_HONEYPOT_ENABLED", false),
		HoneypotDir:     envOr("LEITWACHT_CE_HONEYPOT_DIR", "/var/lib/leitwacht/honeypot"),
		RecordEnvNames:  envBool("LEITWACHT_CE_RECORD_ENV_NAMES", false),
		StdoutEnabled:   envBool("LEITWACHT_CE_STDOUT_ENABLED", true),
		PromEnabled:     envBool("LEITWACHT_CE_PROM_ENABLED", true),
		PromAddr:        envOr("LEITWACHT_CE_PROM_ADDR", ":9090"),
		WebhookURL:      os.Getenv("LEITWACHT_CE_WEBHOOK_URL"),
		WebhookAuth:     os.Getenv("LEITWACHT_CE_WEBHOOK_AUTH"),
		LogLevel:        envOr("LEITWACHT_CE_LOG_LEVEL", "info"),
	}

	c.MaxConcurrentEnf = envInt("LEITWACHT_CE_MAX_CONCURRENT", 64)
	c.EventBuffer = envInt("LEITWACHT_CE_EVENT_BUFFER", 64)

	bucket, err := envDuration("LEITWACHT_CE_BUCKET_INTERVAL", 5*time.Minute)
	if err != nil {
		return nil, err
	}
	c.BucketInterval = bucket

	grace, err := envDuration("LEITWACHT_CE_NETNS_GRACE", 30*time.Second)
	if err != nil {
		return nil, err
	}
	c.NetnsGrace = grace

	wto, err := envDuration("LEITWACHT_CE_WEBHOOK_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.WebhookTimeout = wto

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate returns an error if the config is internally inconsistent or
// required fields are missing.
func (c *Config) Validate() error {
	if c.RulesPath == "" {
		return errors.New("LEITWACHT_CE_RULES_PATH is required")
	}
	if c.DNSUpstream == "" {
		return errors.New("LEITWACHT_CE_DNS_UPSTREAM is required " +
			"(comma-separated host:port list — point at your cluster DNS, " +
			"e.g., the kube-dns ClusterIP, not a public resolver)")
	}
	if c.ContainerRuntime != "docker" && c.ContainerRuntime != "containerd" {
		return fmt.Errorf("LEITWACHT_CE_CONTAINER_RUNTIME = %q (must be docker|containerd)",
			c.ContainerRuntime)
	}
	switch strings.ToLower(c.DefaultAction) {
	case "allow", "block", "audit":
	default:
		return fmt.Errorf("LEITWACHT_CE_DEFAULT_ACTION = %q (must be allow|block|audit)",
			c.DefaultAction)
	}
	switch strings.ToLower(c.UnknownProjectMode) {
	case "enforce", "pass":
	default:
		return fmt.Errorf("LEITWACHT_CE_UNKNOWN_PROJECT = %q (must be enforce|pass)",
			c.UnknownProjectMode)
	}
	if c.MaxConcurrentEnf < 1 {
		return fmt.Errorf("LEITWACHT_CE_MAX_CONCURRENT = %d (must be >= 1)", c.MaxConcurrentEnf)
	}
	if c.EventBuffer < 1 {
		return fmt.Errorf("LEITWACHT_CE_EVENT_BUFFER = %d (must be >= 1)", c.EventBuffer)
	}
	if c.BucketInterval <= 0 {
		return fmt.Errorf("LEITWACHT_CE_BUCKET_INTERVAL = %s (must be > 0)", c.BucketInterval)
	}
	if c.NetnsGrace < 0 {
		return fmt.Errorf("LEITWACHT_CE_NETNS_GRACE = %s (must be >= 0)", c.NetnsGrace)
	}
	if err := validateCIDRList(c.TrustedCIDRs); err != nil {
		return fmt.Errorf("LEITWACHT_CE_TRUSTED_CIDRS: %w", err)
	}
	return nil
}

// validateCIDRList ensures every comma-separated entry parses as a
// CIDR. Empty input is valid. Called from Validate so misconfigured
// CIDRs surface at boot rather than silently leaving an enforcement
// gap (the runtime parse function logs and skips invalid entries).
func validateCIDRList(raw string) error {
	if raw == "" {
		return nil
	}
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
	}
	return nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off", "":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
