//go:build linux

package main

import (
	"context"
	"log/slog"
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
func startBuildKitAttribution(ctx context.Context, cfg *config.Config, log *slog.Logger) {
	if cfg.BuildkitGRPCAddr == "" {
		return
	}

	registry := enforcer.NewSessionRegistry(buildKitSessionTTL)

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

	cgroupPaths := splitTrim(cfg.BuildkitCgroupPaths, ",")
	if len(cgroupPaths) > 0 {
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
			"cgroup_paths", strings.Join(cgroupPaths, ","),
		)
	} else {
		log.Warn("buildkit attribution active without cgroup-join "+
			"(LEITWACHT_CE_BUILDKIT_CGROUP_PATHS is empty); "+
			"sessions and vertices will be tracked but egress events "+
			"will not carry per-vertex attribution",
			"grpc_addr", cfg.BuildkitGRPCAddr,
		)
	}
}
