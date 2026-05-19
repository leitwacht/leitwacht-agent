//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
// Returns the BuildKitEgressAttach (or nil when not started) so main()
// can Close() it during shutdown. Returning nil-error nil-attach is
// the documented "feature disabled" outcome.
func startBuildKitAttribution(
	ctx context.Context,
	cfg *config.Config,
	log *slog.Logger,
	mgr *enforcer.Manager,
) (*enforcer.BuildKitEgressAttach, error) {
	if cfg.BuildkitGRPCAddr == "" {
		return nil, nil //nolint:nilnil // documented disable
	}

	registry := enforcer.NewSessionRegistry(buildKitSessionTTL)

	if cfg.BuildkitRequireCIMetadata {
		required := resolveRequiredAttrs(cfg.BuildkitRequiredAttrs)
		registry.SetCIRequirement(true, required)

		log.Info("buildkit kill-switch active: refusing sessions without required CI metadata",
			"required_attrs", strings.Join(required, ","),
		)
	}

	if denyPatterns := compileDenyVertexPatterns(cfg.BuildkitDenyVertexPatterns, log); len(denyPatterns) > 0 {
		registry.SetBuildVertexDenyPatterns(denyPatterns)

		log.Info("buildkit per-vertex kill-switch active",
			"pattern_count", len(denyPatterns),
			"patterns", cfg.BuildkitDenyVertexPatterns,
		)
	}

	watcher := enforcer.NewAttributionWatcher(cfg.BuildkitGRPCAddr, registry, log)

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

	rawPatterns := splitTrim(cfg.BuildkitCgroupPaths, ",")
	cgroupPaths := expandCgroupGlobs(rawPatterns, log)

	switch {
	case len(cgroupPaths) > 0:
		source := enforcer.NewInotifyCgroupSource(cgroupPaths)
		joiner := enforcer.NewCgroupJoiner(registry, source, log)

		go func() {
			err := joiner.Run(ctx)
			if err != nil && ctx.Err() == nil {
				log.Error("buildkit cgroup joiner exited", "error", err)
			}
		}()

		log.Info("buildkit attribution active",
			"grpc_addr", cfg.BuildkitGRPCAddr,
			"cgroup_patterns", strings.Join(rawPatterns, ","),
			"cgroup_paths_resolved", strings.Join(cgroupPaths, ","),
		)
	case len(rawPatterns) > 0:
		log.Warn("buildkit attribution: cgroup patterns supplied but no paths matched; cgroup-join disabled",
			"grpc_addr", cfg.BuildkitGRPCAddr,
			"cgroup_patterns", strings.Join(rawPatterns, ","),
		)
	default:
		log.Warn("buildkit attribution active without cgroup-join "+
			"(LEITWACHT_CE_BUILDKIT_CGROUP_PATHS is empty); "+
			"sessions and vertices will be tracked but egress events "+
			"will not carry per-vertex attribution",
			"grpc_addr", cfg.BuildkitGRPCAddr,
		)
	}

	// Cgroup-level egress attach. The joiner above populates the
	// SessionRegistry with cgroup_id → vertex bindings; the attach
	// loads a manager-owned eBPF egress filter at the same cgroup
	// parents so RUN-step traffic actually reaches LookupBuildKitBinding
	// in the ringbuf reader.
	//
	// Opt-out (LEITWACHT_CE_BUILDKIT_DISABLE_CGROUP_ATTACH=true):
	// keeps the registry/watcher/joiner running but skips the eBPF
	// load. Effectively disables BuildKit egress observation + future
	// enforcement; useful when the cgroup_skb attach isn't supported
	// (cgroup v1, exotic namespacing) and the operator prefers
	// session/vertex tracking only over a startup error.
	if cfg.BuildkitDisableCgroupAttach {
		log.Info("buildkit cgroup-level attach disabled by config; sessions tracked, egress unobserved",
			"reason", "LEITWACHT_CE_BUILDKIT_DISABLE_CGROUP_ATTACH=true",
		)

		return nil, nil //nolint:nilnil // documented disable
	}

	if len(cgroupPaths) == 0 {
		return nil, nil //nolint:nilnil // nothing to attach to
	}

	attach, err := enforcer.StartBuildKitEgressAttach(
		ctx,
		mgr.Platform(),
		cgroupPaths,
		log,
		mgr.ReportFunc,
		mgr.BucketInterval,
	)
	if err != nil {
		return nil, fmt.Errorf("buildkit egress attach: %w", err)
	}

	log.Info("buildkit egress attach active",
		"cgroup_paths", strings.Join(cgroupPaths, ","),
		"bucket_interval", mgr.BucketInterval,
	)

	return attach, nil
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

// expandCgroupGlobs walks each configured cgroup pattern and resolves
// it to concrete paths via filepath.Glob, deduplicating the result.
// Plain (non-glob) paths flow through unchanged when they exist; a
// non-existent plain path is logged at WARN but otherwise dropped.
// Glob patterns that match zero paths log at WARN (operators tend to
// notice "no buildkitd seen yet" better than a silent skip).
//
// Operators in K8s pass shapes like:
//
//	/sys/fs/cgroup/kubepods.slice/**/buildkit
//	/sys/fs/cgroup/system.slice/docker-*.scope/buildkit
//
// The Go stdlib glob supports `*` per path component but not the
// `**` operator. We approximate `**` by treating it as `*` per
// component during pattern walk: callers that want deep wildcards
// should write a `*` per directory level (e.g.,
// `kubepods.slice/*/*/buildkit`) or use a wrapper that pre-expands.
func expandCgroupGlobs(patterns []string, log *slog.Logger) []string {
	if len(patterns) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))

	for _, p := range patterns {
		if !strings.ContainsAny(p, "*?[") {
			info, err := os.Stat(p)
			if err != nil || !info.IsDir() {
				log.Warn("buildkit cgroup path missing or not a directory; skipping",
					"path", p, "error", err)

				continue
			}

			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}

			continue
		}

		matches, err := filepath.Glob(p)
		if err != nil {
			log.Warn("buildkit cgroup glob is malformed; skipping",
				"pattern", p, "error", err)

			continue
		}

		if len(matches) == 0 {
			log.Warn("buildkit cgroup glob matched zero paths",
				"pattern", p)

			continue
		}

		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}

			if _, dup := seen[m]; !dup {
				seen[m] = struct{}{}
				out = append(out, m)
			}
		}
	}

	return out
}
