// leitwacht-initc is the CI job pod's init container. It blocks main
// container startup until it observes the agent's per-netns DNS proxy
// answering _leitwacht.attached.local with "attached version=<X>" in a
// TXT record. No RPC, no socket, no hostPath; just DNS observation.
//
// Compared to the prior socket-RPC design, this path gives up
// pod-identity binding via SO_PEERCRED (we trust the init code, not
// the peer) in exchange for:
//
//   - PSA-baseline compatibility (no hostPath on CI pods)
//   - independence from cgroup-namespace visibility quirks (Talos)
//   - no filesystem permission dance on the agent socket
//
// The binary is static-compiled + scratch-imaged, identical deployment
// shape as the retired version — the *mechanism* changed, the image
// contract didn't.
//
// On success: emits a structured JSON line to stderr with the agent's
// reported version and exits 0.
// On timeout: emits a structured error with the last-seen DNS state
// and exits 1. Operators grep Loki for `"leitwacht did not attach"`.
// On version incompatibility: emits a structured error and exits 3.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gitlab.com/leitwacht/leitwacht-agent/agentcore/version"
)

const (
	// defaultName has a trailing dot on purpose. Without it, K8s pod
	// resolvers (ndots:5) walk the search list first — every probe
	// produces _leitwacht.attached.local.<ns>.svc.cluster.local et al.
	// before reaching the bare name, and each variant pollutes the
	// agent's DNS proxy with non-matching queries that look like
	// blocked egress under a deny-all policy. The trailing dot marks
	// the name as absolute and skips expansion.
	defaultName     = "_leitwacht.attached.local."
	defaultDeadline = 20 * time.Second
	defaultPoll     = 200 * time.Millisecond
	attachedPrefix  = "attached"

	// semverParts is the number of dot-separated components parseVersion
	// expects. Named so the callers aren't strewn with magic threes.
	semverParts = 3

	exitTimeout     = 1
	exitBadFlag     = 2
	exitIncompatVer = 3
)

func main() {
	os.Exit(run())
}

func run() int {
	nameFlag := flag.String("name", envOr("LEITWACHT_ATTACHED_NAME", defaultName),
		"DNS name whose TXT record is polled for the attached signal")
	deadlineFlag := flag.String("deadline", envOr("LEITWACHT_INIT_DEADLINE", defaultDeadline.String()),
		"overall deadline; init fails if attach is not observed in this window")
	pollFlag := flag.String("poll", envOr("LEITWACHT_INIT_POLL", defaultPoll.String()),
		"interval between DNS probes")

	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	deadline, err := time.ParseDuration(*deadlineFlag)
	if err != nil {
		log.Error("parse deadline", "value", *deadlineFlag, "error", err.Error())

		return exitBadFlag
	}

	poll, err := time.ParseDuration(*pollFlag)
	if err != nil {
		log.Error("parse poll", "value", *pollFlag, "error", err.Error())

		return exitBadFlag
	}

	log.Info("leitwacht-initc starting",
		"name", *nameFlag,
		"deadline", deadline.String(),
		"poll", poll.String(),
		"init_version", version.Version,
		"init_commit", version.Commit,
	)

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	return poll_(ctx, log, *nameFlag, poll, deadline)
}

// poll_ runs the observation loop. Returns the process exit code.
//
//nolint:revive // trailing underscore avoids shadowing the "poll" duration
func poll_(ctx context.Context, log *slog.Logger, name string, interval, deadline time.Duration) int {
	var (
		lastErr    error
		lastAnswer string
	)

	for {
		agentVer, attached, answer, err := probe(ctx, name, interval)
		if answer != "" {
			lastAnswer = answer
		}

		if err != nil {
			lastErr = err
		}

		if attached {
			ok, reason := checkVersion(agentVer, version.Version)
			if !ok {
				log.Error("leitwacht agent version incompatible with this init",
					"agent_version", agentVer,
					"init_version", version.Version,
					"reason", reason,
					"hint", "upgrade the leitwacht agent DaemonSet on this node",
				)

				return exitIncompatVer
			}

			log.Info("leitwacht attached",
				"name", name,
				"agent_version", agentVer,
				"init_version", version.Version,
				"compat", reason,
			)

			return 0
		}

		select {
		case <-ctx.Done():
			log.Error("leitwacht did not attach within deadline — main container will not start",
				"deadline", deadline.String(),
				"last_error", errString(lastErr),
				"last_answer", lastAnswer,
				"init_version", version.Version,
				"hint", "verify the agent DaemonSet on this node matches this init's version",
			)

			return exitTimeout
		case <-time.After(interval):
		}
	}
}

// probe runs one DNS TXT lookup and reports (agentVersion, attachedSeen,
// rawAnswer, err). A nil err with attached=false means the name resolved
// but no TXT record starts with attachedPrefix — cluster DNS answered
// something, just not ours.
func probe(ctx context.Context, name string, timeout time.Duration) (string, bool, string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	txts, err := net.DefaultResolver.LookupTXT(lookupCtx, name)
	if err != nil {
		return "", false, "", fmt.Errorf("lookup TXT %s: %w", name, err)
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, attachedPrefix) {
			continue
		}

		return extractVersion(txt), true, txt, nil
	}

	var last string
	if len(txts) > 0 {
		last = txts[len(txts)-1]
	}

	return "", false, last, nil
}

// extractVersion pulls "X" out of a TXT record shaped like
// "attached version=X [anything else]". Returns "" if no version=
// field is present.
func extractVersion(txt string) string {
	for field := range strings.FieldsSeq(txt) {
		v, ok := strings.CutPrefix(field, "version=")
		if ok {
			return v
		}
	}

	return ""
}

// checkVersion reports whether the agent's reported version is
// compatible with the init's own compiled-in version. Policy:
// agent >= init.
//
// Returns (ok, reason). When either side is not in X.Y.Z shape (e.g.
// "dev" builds, commit SHAs, "-dirty" suffixes in non-standard form),
// we PASS the check rather than wedge operators on local-dev images —
// reason carries a hint so the success log shows why.
func checkVersion(agentVer, requiredVer string) (bool, string) {
	a := parseVersion(agentVer)
	r := parseVersion(requiredVer)

	if a == nil || r == nil {
		return true, "one or both versions not in X.Y.Z form — check skipped"
	}

	if compareVersions(a, r) < 0 {
		return false, fmt.Sprintf("%s < %s (init requires agent >= its own version)", agentVer, requiredVer)
	}

	return true, fmt.Sprintf("%s >= %s", agentVer, requiredVer)
}

// parseVersion returns [major, minor, patch] from a "vX.Y.Z" or "X.Y.Z"
// string. Trailing suffixes after the third number (e.g. "-rc1",
// "-dirty") are tolerated. Returns nil on any parse failure.
func parseVersion(s string) []int {
	s = strings.TrimPrefix(s, "v")

	parts := strings.SplitN(s, ".", semverParts)
	if len(parts) < semverParts {
		return nil
	}

	out := make([]int, semverParts)

	for i, p := range parts {
		end := len(p)

		for j, c := range p {
			if c < '0' || c > '9' {
				end = j

				break
			}
		}

		if end == 0 {
			return nil
		}

		n, err := strconv.Atoi(p[:end])
		if err != nil {
			return nil
		}

		out[i] = n
	}

	return out
}

func compareVersions(lhs, rhs []int) int {
	for i := range semverParts {
		if lhs[i] < rhs[i] {
			return -1
		}

		if lhs[i] > rhs[i] {
			return 1
		}
	}

	return 0
}

func envOr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	return v
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
