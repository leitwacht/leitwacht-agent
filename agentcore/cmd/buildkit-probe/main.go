// buildkit-probe is a dev tool that connects to a real buildkitd and
// prints session/vertex events as they flow through the
// AttributionWatcher. Use it to confirm Phase 1 of step attribution
// works against your local BuildKit before wiring it into agent-ce.
//
// Usage:
//
//	go run ./agentcore/cmd/buildkit-probe -addr tcp://127.0.0.1:1234
//
// In another terminal, drive a build:
//
//	docker buildx build --no-cache -f Dockerfile.probe .
//
// Each STARTED / vertex update / COMPLETE event prints a line. Ctrl+C
// to exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/enforcer"
)

func main() {
	addr := flag.String("addr", "tcp://127.0.0.1:1234", "buildkitd gRPC address (tcp://host:port or unix:///path)")
	pollInterval := flag.Duration("poll", 300*time.Millisecond, "registry snapshot interval")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	registry := enforcer.NewSessionRegistry(2 * time.Minute)

	watcher := enforcer.NewAttributionWatcher(*addr, registry, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "buildkit-probe: connecting to %s\n", *addr)
	fmt.Fprintln(os.Stderr, "buildkit-probe: drive a build in another terminal (Ctrl+C to exit)")
	fmt.Fprintln(os.Stderr, "---")

	go func() {
		err := watcher.Run(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Error("watcher exited", "error", err)
		}
	}()

	pollRegistry(ctx, registry, *pollInterval)
}

// pollRegistry diff-prints registry state at each tick so the operator
// sees new sessions, new vertices, vertex completions, and session
// completions as they happen.
func pollRegistry(ctx context.Context, registry *enforcer.SessionRegistry, interval time.Duration) {
	type vertexKey struct{ ref, digest string }

	seenSessions := map[string]bool{}
	seenVertices := map[vertexKey]bool{}
	completedVertices := map[vertexKey]bool{}
	completedSessions := map[string]bool{}

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
	}
}

func shortDigest(d string) string {
	const algoLen = len("sha256:")
	if len(d) > algoLen+12 {
		return d[:algoLen+12]
	}

	return d
}
