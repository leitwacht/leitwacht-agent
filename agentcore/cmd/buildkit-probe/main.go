// buildkit-probe is a dev tool that drives the agent's BuildKit
// attribution stack against a real buildkitd. It exercises both
// Phase 1 (Control.Status subscriber → SessionRegistry) and Phase 2
// (cgroup-to-vertex join → cgroup_id index) without requiring the
// rest of agent-ce, eBPF, or root.
//
// Usage:
//
//	# Phase 1 only — observe vertex events.
//	go run ./agentcore/cmd/buildkit-probe -addr tcp://127.0.0.1:1234
//
//	# Phase 1 + Phase 2 — observe cgroup_id → vertex bindings live.
//	# (Read access to the cgroup paths required; root usually not needed
//	# for cgroup v2 unified hierarchies.)
//	go run ./agentcore/cmd/buildkit-probe \
//	    -addr tcp://127.0.0.1:1234 \
//	    -cgroup-paths /sys/fs/cgroup/system.slice/docker-<id>.scope/buildkit
//
// Each session/vertex/cgroup event prints one line. Ctrl+C to exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

func main() {
	addr := flag.String("addr", "tcp://127.0.0.1:1234", "buildkitd gRPC address (tcp://host:port or unix:///path)")
	cgroupPaths := flag.String("cgroup-paths", "", "comma-separated cgroup parent paths to watch for RUN-container creates (enables Phase 2 cgroup-join)")
	pollInterval := flag.Duration("poll", 300*time.Millisecond, "registry snapshot interval")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	registry := enforcer.NewSessionRegistry(2 * time.Minute)

	watcher := enforcer.NewAttributionWatcher(*addr, registry, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "buildkit-probe: connecting to %s\n", *addr)

	paths := splitNonEmpty(*cgroupPaths)
	if len(paths) > 0 {
		fmt.Fprintf(os.Stderr, "buildkit-probe: cgroup-join watching %v\n", paths)
	} else {
		fmt.Fprintln(os.Stderr, "buildkit-probe: cgroup-join disabled (pass -cgroup-paths to enable)")
	}

	fmt.Fprintln(os.Stderr, "buildkit-probe: drive a build in another terminal (Ctrl+C to exit)")
	fmt.Fprintln(os.Stderr, "---")

	go func() {
		err := watcher.Run(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Error("watcher exited", "error", err)
		}
	}()

	if len(paths) > 0 {
		source := enforcer.NewInotifyCgroupSource(paths)
		joiner := enforcer.NewCgroupJoiner(registry, source, logger)

		go func() {
			err := joiner.Run(ctx)
			if err != nil && ctx.Err() == nil {
				logger.Error("cgroup joiner exited", "error", err)
			}
		}()
	}

	pollRegistry(ctx, registry, *pollInterval)
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")

	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}

// pollRegistry diff-prints registry state at each tick so the operator
// sees new sessions, new vertices, vertex completions, session
// completions, and cgroup→vertex bindings as they happen.
func pollRegistry(ctx context.Context, registry *enforcer.SessionRegistry, interval time.Duration) {
	type vertexKey struct{ ref, digest string }

	seenSessions := map[string]bool{}
	seenVertices := map[vertexKey]bool{}
	completedVertices := map[vertexKey]bool{}
	completedSessions := map[string]bool{}
	seenCgroups := map[uint64]bool{}

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "---")
			fmt.Fprintln(os.Stderr, "buildkit-probe: shutting down")

			return
		case <-tick.C:
		}

		snap := registry.Snapshot()

		refs := make([]string, 0, len(snap))
		for ref := range snap {
			refs = append(refs, ref)
		}

		sort.Strings(refs)

		for _, ref := range refs {
			s := snap[ref]

			if !seenSessions[ref] {
				seenSessions[ref] = true

				attrs := ""
				if target, ok := s.FrontendAttrs["target"]; ok {
					attrs = fmt.Sprintf(" target=%q", target)
				}

				fmt.Printf("[%s] SESSION STARTED ref=%s%s\n", time.Now().Format("15:04:05.000"), ref, attrs)
			}

			digests := make([]string, 0, len(s.Vertices))
			for d := range s.Vertices {
				digests = append(digests, d)
			}

			sort.Strings(digests)

			for _, d := range digests {
				v := s.Vertices[d]
				k := vertexKey{ref, d}

				if !seenVertices[k] {
					seenVertices[k] = true

					fmt.Printf("[%s] VERTEX  STARTED ref=%s digest=%s name=%q\n",
						time.Now().Format("15:04:05.000"), ref, shortDigest(d), v.Name)
				}

				if v.Completed && !completedVertices[k] {
					completedVertices[k] = true

					cached := ""
					if v.Cached {
						cached = " (cached)"
					}

					fmt.Printf("[%s] VERTEX  DONE    ref=%s digest=%s%s\n",
						time.Now().Format("15:04:05.000"), ref, shortDigest(d), cached)
				}
			}

			if s.Completed && !completedSessions[ref] {
				completedSessions[ref] = true

				fmt.Printf("[%s] SESSION DONE    ref=%s\n", time.Now().Format("15:04:05.000"), ref)
			}
		}

		for cgID, binding := range registry.CgroupSnapshot() {
			if seenCgroups[cgID] {
				continue
			}

			seenCgroups[cgID] = true

			ambig := ""
			if binding.Ambiguous {
				ambig = fmt.Sprintf(" AMBIGUOUS candidates=%d", len(binding.AmbiguousCandidates))
			}

			fmt.Printf("[%s] CGROUP  LINKED  cgroup_id=%d container=%s → ref=%s digest=%s name=%q%s\n",
				time.Now().Format("15:04:05.000"),
				cgID, binding.ContainerID,
				binding.SessionRef, shortDigest(binding.VertexDigest), binding.VertexName,
				ambig,
			)
		}
	}
}

func shortDigest(d string) string {
	const algoLen = len("sha256:")
	if len(d) > algoLen+12 {
		return d[:algoLen+12]
	}

	return d
}
