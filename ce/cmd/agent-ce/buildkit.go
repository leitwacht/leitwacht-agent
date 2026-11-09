//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
	"gitlab.com/leitwacht/leitwacht-agent/ce/config"
)

// buildKitSessionTTL is how long the registry keeps completed sessions
// around. Long enough to attribute late-arriving egress events from
// processes whose cgroup outlives the COMPLETE event, short enough
// that an idle daemon doesn't accumulate ghost sessions.
const buildKitSessionTTL = 2 * time.Minute

// startBuildKitAttribution wires the BuildKit Status subscriber and
// cgroup-to-vertex joiner into the running daemon when configured.
//
// When LEITWACHT_CE_BUILDKIT_GRPC_ADDR is empty (the default), this
// function is a no-op: the package-level LookupBuildKitBinding hook
// stays at its zero-value default and the enforcer's egress path
// continues to emit violations without BuildKit attribution fields.
//
// When the GRPC address is set, the agent:
//   - subscribes to the buildkitd Control gRPC (sessions, vertices),
//   - installs the registry's cgroup_id → binding lookup as the
//     hot-path hook the egress event handler queries,
//   - optionally watches BuildKit's cgroup-parent paths via inotify
//     and links each new RUN cgroup to its vertex on the fly.
//
// Cgroup-join is gated separately on LEITWACHT_CE_BUILDKIT_CGROUP_PATHS
// because the right path is deployment-specific (docker-in-docker,
// rootless buildkitd, k8s daemonset, etc). With the grpc address set
// but no cgroup paths, the registry tracks sessions and vertices but
// egress events stay unattributed at the cgroup level — useful for
// confirming Phase 1 wiring before tuning the path.
//
// Returns the CgroupResolver (or nil when not started) so main() can
// Close() it during shutdown (it owns the joiner and egress attach).
// Returning nil-error nil-resolver is the documented "feature
// disabled" outcome.
func startBuildKitAttribution(
	ctx context.Context,
	cfg *config.Config,
	log *slog.Logger,
	mgr *enforcer.Manager,
	policySrc enforcer.BuildPolicySource,
) (*enforcer.CgroupResolver, error) {
	if cfg.BuildkitGRPCAddr == "" {
		return nil, nil //nolint:nilnil // documented disable
	}

	if cfg.BuildkitTLSEnabled() && strings.HasPrefix(cfg.BuildkitGRPCAddr, "unix:") {
		return nil, errors.New("buildkit TLS settings cannot be combined with a unix:// " +
			"grpc address: buildkitd serves unix sockets in plaintext")
	}

	registry := enforcer.NewSessionRegistry(buildKitSessionTTL)
	registry.SetMaxSessionAge(cfg.BuildkitMaxSessionAge)

	if cfg.BuildkitRequireCIMetadata {
		required := resolveRequiredAttrs(cfg.BuildkitRequiredAttrs)
		registry.SetCIRequirement(true, required)

		log.Info("buildkit kill-switch active: refusing sessions without required CI metadata",
			"required_attrs", strings.Join(required, ","),
		)
	}

	if denyPatterns := compileDenyVertexPatterns(cfg.BuildkitDenyVertexPatterns, log); len(denyPatterns) > 0 {
		// TODO: these deny patterns apply process-wide, to every build on
		// this buildkitd. Move them into the per-(project, job) policy
		// slot so one project's patterns cannot affect another's builds.
		registry.SetBuildVertexDenyPatterns(denyPatterns)

		log.Info("buildkit per-vertex kill-switch active",
			"pattern_count", len(denyPatterns),
			"patterns", cfg.BuildkitDenyVertexPatterns,
		)
	}

	var watcherOpts []enforcer.WatcherOption

	tlsCfg := enforcer.BuildKitTLSConfig{
		CAFile:     cfg.BuildkitTLSCA,
		CertFile:   cfg.BuildkitTLSCert,
		KeyFile:    cfg.BuildkitTLSKey,
		ServerName: cfg.BuildkitTLSServerName,
	}
	if tlsCfg.Enabled() {
		bkTLS, err := enforcer.LoadBuildKitTLS(tlsCfg, log)
		if err != nil {
			return nil, err
		}

		watcherOpts = append(watcherOpts, enforcer.WithTLS(bkTLS))
	}

	watcher := enforcer.NewAttributionWatcher(cfg.BuildkitGRPCAddr, registry, log, watcherOpts...)

	go func() {
		err := watcher.Run(ctx)
		if err != nil && ctx.Err() == nil {
			log.Error("buildkit attribution watcher exited", "error", err)
		}
	}()

	// Install the hot-path lookup. Until this call returns the
	// enforcer's egress path returns (zero, false) from every lookup —
	// fine, because no cgroup bindings exist yet anyway.
	enforcer.SetBuildKitLookup(registry.LookupByCgroupID)
	enforcer.SetBuildKitSessionLookup(registry.SessionsActiveAt)
	enforcer.SetBuildKitEventLookup(registry.LookupForEvent)

	rawPatterns := splitTrim(cfg.BuildkitCgroupPaths, ",")
	if len(rawPatterns) == 0 {
		log.Warn("buildkit attribution active without cgroup-join "+
			"(LEITWACHT_CE_BUILDKIT_CGROUP_PATHS is empty); "+
			"sessions and vertices will be tracked but egress events "+
			"will not carry per-vertex attribution",
			"grpc_addr", cfg.BuildkitGRPCAddr,
		)

		return nil, nil //nolint:nilnil // nothing to attach to
	}

	// buildkitd creates its cgroup parent lazily (first RUN step), so
	// the patterns are re-resolved in the background: the resolver
	// (re)starts the joiner and the egress attach whenever the
	// resolved set becomes non-empty or changes. The startup
	// expansion is synchronous, so an attach failure there stays
	// fatal.
	//
	// Cgroup-level egress attach: the joiner populates the
	// SessionRegistry with cgroup_id -> vertex bindings; the attach
	// loads a manager-owned eBPF egress filter at the same cgroup
	// parents so RUN-step traffic reaches LookupBuildKitBinding.
	//
	// Opt-out (LEITWACHT_CE_BUILDKIT_DISABLE_CGROUP_ATTACH=true):
	// keeps the registry/watcher/joiner running but skips the eBPF
	// load. Useful when cgroup_skb attach isn't supported (cgroup v1,
	// exotic namespacing) and the operator prefers session/vertex
	// tracking only over a startup error.
	rc := enforcer.CgroupResolverConfig{
		Patterns: rawPatterns,
		Logger:   log,
		LogAttrs: []any{
			"grpc_addr", cfg.BuildkitGRPCAddr,
			"cgroup_patterns", strings.Join(rawPatterns, ","),
		},
		NewJoiner: func(paths []string, scanExisting bool) enforcer.JoinerRunner {
			src := enforcer.NewInotifyCgroupSource(paths)
			src.ScanExisting = scanExisting

			return enforcer.NewCgroupJoiner(registry, src, log,
				enforcer.WithKillOnUnattributed(cfg.BuildkitKillOnUnattributed))
		},
	}

	if cfg.BuildkitDisableCgroupAttach {
		log.Info("buildkit cgroup-level attach disabled by config; sessions tracked, egress unobserved",
			"reason", "LEITWACHT_CE_BUILDKIT_DISABLE_CGROUP_ATTACH=true",
		)
	} else {
		rc.StartAttach = func(ctx context.Context, paths []string) (io.Closer, error) {
			opts := []enforcer.BuildKitAttachOption{
				enforcer.WithBuildKitRegistry(registry),
				enforcer.WithBuildPolicySource(policySrc),
				// Port 53 from build steps is pinned to the DNS upstream in
				// shadow/enforce; trusted networks are not used for DNS.
				enforcer.WithBuildKitDNSUpstreams(splitTrim(cfg.DNSUpstream, ",")),
			}

			if cfg.BuildkitDNSProxy {
				opts = append(opts, enforcer.WithBuildKitDNSProxy(enforcer.BuildDNSConfig{
					Tracker:              mgr.DNSPIDTracker(),
					ProcName:             cfg.BuildkitDNSProc,
					ProcCgroupContains:   cfg.BuildkitDNSProcCgroup,
					ListenAddr:           cfg.BuildkitDNSListen,
					Upstreams:            splitTrim(cfg.DNSUpstream, ","),
					ClusterDomain:        cfg.ClusterDomain,
					ExpansionSuppression: cfg.DNSExpansionSuppression,
					CacheSize:            mgr.DNSCacheSize,
				}))
			}

			// Shadow/enforce need the operator's trusted networks (cluster
			// DNS, registry mirrors) or every build connection to them
			// would be judged by rules. In audit they stay unlisted so
			// every connection is still observed, as before.
			if cfg.BuildkitEnforcement != "" && cfg.BuildkitEnforcement != "audit" {
				opts = append(opts, enforcer.WithBuildKitTrustedCIDRs(parseTrustedCIDRs(cfg.TrustedCIDRs, log)))
			}

			a, err := enforcer.StartBuildKitEgressAttach(
				ctx, mgr.Platform(), paths, log, mgr.ReportFunc, mgr.BucketInterval, opts...)
			if err != nil {
				return nil, fmt.Errorf("buildkit egress attach: %w", err)
			}

			if a == nil {
				return nil, nil //nolint:nilnil // no paths: nothing to close
			}

			log.Info("buildkit egress attach active",
				"cgroup_paths", strings.Join(paths, ","),
				"bucket_interval", mgr.BucketInterval,
			)

			return a, nil
		}
	}

	resolver := enforcer.NewCgroupResolver(rc)
	if err := resolver.Start(ctx); err != nil {
		return nil, err
	}

	return resolver, nil
}

// compileDenyVertexPatterns parses the comma-separated regex list from
// LEITWACHT_CE_BUILDKIT_DENY_VERTEX_PATTERNS into compiled regexp
// values. Invalid patterns are skipped with a WARN log — the rest
// flow through, so a typo in one pattern doesn't disable the policy
// entirely. Empty input returns nil.
func compileDenyVertexPatterns(raw string, log *slog.Logger) []*regexp.Regexp {
	plain := splitTrim(raw, ",")
	if len(plain) == 0 {
		return nil
	}

	out := make([]*regexp.Regexp, 0, len(plain))
	for _, p := range plain {
		re, err := regexp.Compile(p)
		if err != nil {
			log.Warn("buildkit deny vertex pattern invalid; skipping",
				"pattern", p, "error", err)

			continue
		}

		out = append(out, re)
	}

	return out
}

// resolveRequiredAttrs turns the comma-separated
// LEITWACHT_CE_BUILDKIT_REQUIRED_ATTRS env value into the
// FrontendAttrs-prefixed key list the SessionRegistry expects.
// Empty input falls back to the safe minimum (just project_path —
// the routing key on the server). Keys are uppercased + trimmed and
// the "build-arg:" prefix is added so callers pass plain names like
// "LEITWACHT_CI_PROJECT_PATH".
func resolveRequiredAttrs(raw string) []string {
	plain := splitTrim(raw, ",")
	if len(plain) == 0 {
		plain = []string{"LEITWACHT_CI_PROJECT_PATH"}
	}

	out := make([]string, 0, len(plain))
	for _, k := range plain {
		k = strings.ToUpper(k)
		out = append(out, "build-arg:"+k)
	}

	return out
}
