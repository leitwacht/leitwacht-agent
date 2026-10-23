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
	CredwatchEnabled   bool
	CredwatchPaths     string // comma-separated path suffixes to watch
	CredwatchExclude   string // comma-separated path suffixes to exclude
	ProcMemEnabled     bool
	RecordEnvNames     bool // when true, attach env-var NAMES (never values) to each Violation report
	MaxConcurrentEnf   int
	EventBuffer        int           // size of the watcher's event channel; back-pressures containerd subscriptions when full
	NetnsGrace         time.Duration // how long a netns context survives after its last container detaches
	FreezeTimeout      time.Duration // pre-attach container freeze budget; 0 disables the freeze
	FreezeStateDir     string        // where freeze markers are persisted for crash recovery; empty = built-in default
	BucketInterval     time.Duration

	// Sinks.
	StdoutEnabled  bool
	PromEnabled    bool
	PromAddr       string // ":9090"
	WebhookURL     string
	WebhookAuth    string // "Bearer ..." passed verbatim if non-empty
	WebhookTimeout time.Duration

	// BuildKit step attribution. Optional — empty BuildkitGRPCAddr
	// disables the whole subsystem and the agent behaves exactly
	// as it did before BuildKit attribution existed. When set, the
	// agent subscribes to the buildkitd Control gRPC for build
	// session/vertex metadata. BuildkitCgroupPaths is the
	// comma-separated list of cgroup-parent directories to watch
	// for RUN-container creates — usually the host-side path of
	// buildkitd's per-build cgroup tree. Glob patterns are
	// expanded at startup (one `*` per directory level).
	BuildkitGRPCAddr    string
	BuildkitCgroupPaths string

	// BuildkitRequireCIMetadata, when true, makes the agent refuse
	// any Solve session whose FrontendAttrs lack all of
	// BuildkitRequiredAttrs. RUN cgroups linked to a refused session
	// are SIGKILLed via cgroup.kill the moment they appear, so the
	// build fails before any egress happens. Default false — back-
	// compat. Recommended ON for the persistent K8s buildkitd
	// pattern where every CI job is expected to inject CI metadata
	// via --build-arg LEITWACHT_CI_*=...; turning this on prevents
	// builds that skipped the metadata from running unattributed.
	BuildkitRequireCIMetadata bool

	// BuildkitRequiredAttrs is the comma-separated list of
	// LEITWACHT_CI_* env keys a session's FrontendAttrs must carry
	// to pass the kill-switch when BuildkitRequireCIMetadata=true.
	// Empty means the default of "LEITWACHT_CI_PROJECT_PATH" — the
	// minimum needed for server-side routing. Operators can require
	// more (e.g., "LEITWACHT_CI_PROJECT_PATH,LEITWACHT_CI_JOB_ID")
	// if they want stricter policy.
	BuildkitRequiredAttrs string

	// BuildkitDisableCgroupAttach, when true, skips the manager-side
	// eBPF attach at the BuildKit RUN-step cgroup parents. The agent
	// still subscribes to buildkitd's Control gRPC and tracks
	// sessions + vertices in the registry, but no egress observation
	// happens for RUN-step processes — which means no per-RUN-step
	// attribution and no kill-switch enforcement on egress.
	//
	// Operators set this when running on a kernel/runtime combo
	// where attaching cgroup_skb at /sys/fs/cgroup/buildkit fails
	// (e.g. cgroup v1, container-isolated cgroup namespaces) and
	// they prefer observability-only mode over startup errors. The
	// kill-switch on missing CI metadata (BuildkitRequireCIMetadata)
	// still functions because it acts at registry time, not at
	// cgroup-attach time.
	BuildkitDisableCgroupAttach bool

	// BuildkitDenyVertexPatterns is a comma-separated list of
	// regular expressions evaluated against each BuildKit vertex's
	// Name (e.g. "[stage 2/5] RUN apk add curl"). A match SIGKILLs
	// the RUN cgroup via cgroup.kill before any egress can happen —
	// same mechanism as BuildkitRequireCIMetadata. Server-distributed
	// policy rules with PatternType=build_vertex+Action=deny populate
	// the same kill-switch via the EE-side rule fetch; CE installs
	// can pin a static set via this env var.
	//
	// Examples:
	//   LEITWACHT_CE_BUILDKIT_DENY_VERTEX_PATTERNS="^\\[.*\\] RUN npm install"
	//   LEITWACHT_CE_BUILDKIT_DENY_VERTEX_PATTERNS="apt-get,curl https?://"
	BuildkitDenyVertexPatterns string

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
		DNSUpstream:                os.Getenv("LEITWACHT_CE_DNS_UPSTREAM"),
		TrustedCIDRs:               os.Getenv("LEITWACHT_CE_TRUSTED_CIDRS"),
		CredwatchPaths:             envOr("LEITWACHT_CE_CREDWATCH_PATHS", defaultCredwatchPaths),
		CredwatchExclude:           envOr("LEITWACHT_CE_CREDWATCH_EXCLUDE", defaultCredwatchExclude),
		PromAddr:                   envOr("LEITWACHT_CE_PROM_ADDR", ":9090"),
		WebhookURL:                 os.Getenv("LEITWACHT_CE_WEBHOOK_URL"),
		WebhookAuth:                os.Getenv("LEITWACHT_CE_WEBHOOK_AUTH"),
		BuildkitGRPCAddr:           os.Getenv("LEITWACHT_CE_BUILDKIT_GRPC_ADDR"),
		BuildkitCgroupPaths:        os.Getenv("LEITWACHT_CE_BUILDKIT_CGROUP_PATHS"),
		BuildkitRequiredAttrs:      os.Getenv("LEITWACHT_CE_BUILDKIT_REQUIRED_ATTRS"),
		BuildkitDenyVertexPatterns: os.Getenv("LEITWACHT_CE_BUILDKIT_DENY_VERTEX_PATTERNS"),
		LogLevel:                   envOr("LEITWACHT_CE_LOG_LEVEL", "info"),
	}

	var err error

	c.CredwatchEnabled, err = envBool("LEITWACHT_CE_CREDWATCH_ENABLED", false)
	if err != nil {
		return nil, err
	}
	c.ProcMemEnabled, err = envBool("LEITWACHT_CE_PROC_MEM_ENABLED", false)
	if err != nil {
		return nil, err
	}
	c.RecordEnvNames, err = envBool("LEITWACHT_CE_RECORD_ENV_NAMES", false)
	if err != nil {
		return nil, err
	}
	c.StdoutEnabled, err = envBool("LEITWACHT_CE_STDOUT_ENABLED", true)
	if err != nil {
		return nil, err
	}
	c.PromEnabled, err = envBool("LEITWACHT_CE_PROM_ENABLED", true)
	if err != nil {
		return nil, err
	}
	c.BuildkitRequireCIMetadata, err = envBool("LEITWACHT_CE_BUILDKIT_REQUIRE_CI_METADATA", false)
	if err != nil {
		return nil, err
	}
	c.BuildkitDisableCgroupAttach, err = envBool("LEITWACHT_CE_BUILDKIT_DISABLE_CGROUP_ATTACH", false)
	if err != nil {
		return nil, err
	}

	c.MaxConcurrentEnf, err = envInt("LEITWACHT_CE_MAX_CONCURRENT", 64)
	if err != nil {
		return nil, err
	}
	c.EventBuffer, err = envInt("LEITWACHT_CE_EVENT_BUFFER", 64)
	if err != nil {
		return nil, err
	}

	bucket, err := envDuration("LEITWACHT_CE_BUCKET_INTERVAL", 5*time.Minute) //nolint:govet // err is re-declared intentionally to keep the err-check pattern uniform across envBool/envInt/envDuration above
	if err != nil {
		return nil, err
	}
	c.BucketInterval = bucket

	grace, err := envDuration("LEITWACHT_CE_NETNS_GRACE", 30*time.Second)
	if err != nil {
		return nil, err
	}
	c.NetnsGrace = grace

	freeze, err := envDuration("LEITWACHT_CE_FREEZE_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.FreezeTimeout = freeze
	c.FreezeStateDir = os.Getenv("LEITWACHT_CE_FREEZE_STATE_DIR")

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
	if c.FreezeTimeout < 0 {
		return fmt.Errorf("LEITWACHT_CE_FREEZE_TIMEOUT = %s (must be >= 0; 0 disables the pre-attach freeze)", c.FreezeTimeout)
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

// envBool reads a boolean from the environment. Unset → default;
// recognised value → that value; anything else → error so an operator
// typo like LEITWACHT_CE_PROM_ENABLED=yess surfaces at boot rather
// than silently falling back to the default.
func envBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off", "":
		return false, nil
	default:
		return false, fmt.Errorf("%s = %q (must be one of: 1, true, yes, on, 0, false, no, off)", key, v)
	}
}

// envInt — same fail-fast posture as envBool. Unparseable strings
// are operator errors, not silent defaults.
func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s = %q: %w", key, v, err)
	}
	return n, nil
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

const defaultCredwatchPaths = "/.aws/credentials,/.ssh/id_rsa,/.ssh/id_ed25519,/.ssh/id_ecdsa," +
	"/.ssh/config,/.ssh/authorized_keys," +
	"/.kube/config,/.docker/config.json,/.git-credentials," +
	"/.config/gcloud/application_default_credentials.json,/.vault-token," +
	"/.config/gcloud/credentials.db,/.azure/accessTokens.json," +
	"/.terraform.d/credentials.tfrc.json," +
	"/secrets/vault_token,/rancher/k3s/k3s.yaml"

const defaultCredwatchExclude = "/.npmrc,/.netrc,/.pypirc"
