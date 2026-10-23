# BuildKit step-level attribution

**Status:** design accepted, implementation pending
**Scope:** agent (this repo) + EE server + UI (sibling repos)
**Owner:** Thomas
**Last update:** 2026-05-18

## Goal

Attribute every network egress event observed inside a `docker buildx
build` to the specific Dockerfile instruction that produced it (e.g.
`"[build 3/7] RUN apt-get install -y curl"`), **live**, on a
persistent buildkitd daemon shared by multiple CI jobs.

The user-visible outcome: an egress event in the dashboard reads

> `vertex_evil.com:8000` blocked — `[build 5/12] RUN npm ci` —
> session `r_abc123…`, job `gitlab-runner-foo#42`

instead of the current

> `vertex_evil.com:8000` blocked — `docker-buildx`, no further context.

## Background — why this matters

Today the agent attaches eBPF egress filtering to buildkitd's cgroup
and a per-job DNS proxy (see `agentcore/enforcer/buildkit_egress_attach.go`). That
correctly catches build-time egress and attributes it to the
*GitLab job* whose `ReportViolations` is currently active. But it
loses the structure *inside* the build:

- Which Dockerfile RUN fired the egress?
- Which build stage (`FROM AS build` vs `FROM AS final`)?
- Was this from the developer's RUN, or from a transitive postinstall
  hook inside an npm package?

Surfacing the Dockerfile-instruction level inside an opaque
`docker build` is the missing layer of context for both
forensics ("which RUN exfiltrated?") and policy authoring
("only `RUN apt-get …` may reach deb.debian.org"). The agent already
attributes at the cgroup level; this design extends that with
semantic enrichment from BuildKit's own build graph.

## Architectural choice — Pick A

Three candidate architectures were evaluated:

| Pick | Mechanism | Effort | Coverage | Maintenance |
|---|---|---|---|---|
| **A — Status subscriber + cgroup join** | gRPC client to `buildkit.v1.Control` + fanotify on buildkit cgroups + cmdline match | **4–6 weeks** | ~95% of deployments | Low — consumes public APIs |
| **B — Custom runc wrapper** | Replace runc on buildkitd PATH, inject OCI hook for deterministic tuple | 8–10 weeks | docker-container + standalone | Medium — re-test every BuildKit release |
| **C — Fork buildkitd** | Add `Control.Attribution` RPC + first-class hook config | 16–20 weeks + 4–6 wk/yr rebase | Anything running our fork | High — distro responsibility |

**This plan ships Pick A.** Rationale:

- Public-API-only consumer; no PATH hijack, no fork, no distro tax.
- The known fragility (vertex_digest ↔ cgroup_id join under parallel
  cgroup creation) has a robust multi-key tiebreaker (cmdline →
  environ → bundle path → ambiguous-attribution flag).
- For Managed Runners specifically (where cross-tenant misattribution
  is a security concern, not just messy UX), Pick B is brought in as
  a follow-on. Self-hosted single-tenant ships with Pick A only.
- An upstream `SpecOpts.Hooks` PR will be sent to moby/buildkit in
  parallel. If accepted, Pick B becomes a `buildkitd.toml` knob
  rather than a PATH hijack — much cleaner. Independent of Pick A.

Pick C is deliberately deferred indefinitely. Forks are the most
expensive form of "reliability."

## How parallelism is handled (the fragile part)

Two layers of parallelism:

- **Cross-build:** multiple `Solve` sessions in flight on one
  buildkitd. `Control.Status(StatusRequest{Ref})` is keyed by build
  ref — independent streams per session. The session registry is
  `session_ref → {vertex_digest → vertex_state}`, never one global
  vertex pool.
- **Within-build:** vertices run concurrently, capped by
  `--oci-worker-max-parallelism` (default 4× num CPUs ≈ 16–32). At
  peak, several cgroups can appear in `/sys/fs/cgroup/.../buildkit/`
  within milliseconds of each other.

The join algorithm when fanotify fires on a new cgroup:

1. **Primary:** read first PID in `cgroup.procs` → `/proc/<pid>/cmdline`.
   BuildKit invokes `sh -c "<dockerfile command>"`; cmdline carries
   the literal command string from `Vertex.name`. Match against
   started-but-not-yet-joined vertices across all active sessions.
2. **Tiebreaker (identical commands):** read `/proc/<pid>/environ`
   and match against the session's known FrontendAttrs (build-args,
   target stage). Different sessions almost always differ here.
3. **Last-resort fallback:** kprobe `execve` on `runc create` to
   capture the bundle path argv; BuildKit lays bundles under
   per-session directories, so the bundle path discloses the session.
4. **Honest fallback:** when (1)+(2)+(3) all fail (truly identical
   commands + identical env + race-of-millisecond at runc-create),
   emit the egress event with `ambiguous_attribution: ["session_A:vertex_X",
   "session_B:vertex_Y"]`. Forensics value preserved; policy
   enforcement at the session/build level still works (session ref is
   never ambiguous because it comes from the Status stream).

Cross-tenant misattribution under Pick A is acceptable for
self-hosted single-tenant; Managed Runners gates on Pick B before
shipping.

## Components

### Agent-side

```
agentcore/
├── enforcer/
│   ├── buildkit_egress_attach.go (cgroup attach at the BuildKit cgroup parents, audit only)
│   ├── buildkit_attribution.go  (NEW — Status subscriber + session registry)
│   ├── buildkit_cgroup_join.go  (NEW — inotify watcher + argv/environ matching)
│   └── buildkit_*_test.go
└── violation/
    └── ...                      (emit BuildStep field on violation events)
```

External Go deps to add:
- `github.com/moby/buildkit/api/services/control` — gRPC client types
- `github.com/moby/buildkit/client` — high-level `Build`/`Status` helpers
  (probably overkill; can use raw gRPC)
- `golang.org/x/sys/unix` — fanotify API (already a transitive dep)

No new system deps. fanotify needs `CAP_SYS_ADMIN` which the agent
already has for its existing eBPF programs.

### Wire-protocol changes (agentpb)

Add to the existing `Violation` proto (in `contract/agentpb` of the
leitwacht-ee repo — separate change):

```proto
message BuildStepAttribution {
  string session_ref = 1;          // BuildKit build ref
  string vertex_digest = 2;        // LLB content-addressed digest
  string vertex_name = 3;          // human string e.g. "[build 5/12] RUN npm ci"
  string dockerfile_filename = 4;  // when known via Definition
  uint32 dockerfile_line_start = 5;
  uint32 dockerfile_line_end = 6;
  repeated string ambiguous_vertices = 7;  // populated only when join is ambiguous
}

message Violation {
  // ... existing fields ...
  BuildStepAttribution build_step = N;  // optional; populated when egress
                                         // originated inside a buildkit cgroup
}
```

Backwards compatible — older agents and older servers ignore the new
field.

### Server-side ingest + UI

- `internal/store/violations.go`: extend the Violation row with
  `BuildSessionRef`, `BuildVertexName`, `BuildDockerfileLine`,
  `BuildAmbiguous`. ClickHouse migration adds nullable columns.
- `internal/api/readonly.go`: surface build_step on the egress view.
- `frontend/src/lib/EgressLog.svelte`: render `🔨 [build 5/12] RUN npm
  ci` as a chip below the domain/IP, link-out to the build's session
  history.

### Deployment changes

A typical buildkitd Deployment NetworkPolicy blocks ingress except
from the gitlab-runner namespace. Two options:

1. **Widen the NetworkPolicy** to also allow ingress from the
   leitwacht-agent namespace (recommended; one-line change in the
   operator's gitops repo).
2. **Run the BuildKit watcher as a sidecar** in the buildkitd pod
   itself. Lower attack surface (no widened NetworkPolicy) but
   couples agent and buildkitd pod lifecycles.

Option 1 ships first. Option 2 is a hardening follow-up.

## Phases & estimates

### Phase 0 — protocol additions (~3 days)

- Update `contract/agentpb` proto, regenerate Go types.
- Add nullable columns to ClickHouse `violations` table + migration.
- No behavior change. Just plumbing.

**Risks:** ClickHouse schema migrations on the production install
(non-zero downtime). Mitigation: add columns as nullable; old rows
read fine.

### Phase 1 — BuildKit Status subscriber (~1 week)

- New file `agentcore/enforcer/buildkit_attribution.go`.
- gRPC client to `buildkitd:1234`, configurable address.
- `ListenBuildHistory(ActiveOnly=true)` → fan out one goroutine per
  STARTED ref, calling `Status(StatusRequest{Ref})`.
- Session registry keyed by ref; vertex states populated from Status
  events. TTL on completed sessions: 30s drain.
- Reconnect-on-disconnect with jittered backoff. `ListenBuildHistory`
  resumes naturally.
- Unit tests: fake gRPC server emitting canned Status responses; verify
  registry state transitions.

**Risks:** BuildKit's gRPC API moves under us. Mitigation: pin the
proto version; run integration tests against real buildkitd in CI.

### Phase 2 — cgroup-to-vertex join (~1 week)

- New file `agentcore/enforcer/buildkit_cgroup_join.go`.
- inotify on `/sys/fs/cgroup/.../buildkit/` (or
  `/sys/fs/cgroup/system.slice/buildkit-*.scope` under systemd).
- On a directory create, read `cgroup.procs` → first PID → `/proc/<pid>/cmdline`.
- Primary match: the process argv against the `RUN` command of each
  active vertex. The match is exact on the whitespace-normalised
  command (the `-c` argument for shell form, the joined argv for exec
  form, with `RUN --mount=...`-style flags stripped from the vertex
  name); a substring test is deliberately not used.
- Tiebreaker: `/proc/<pid>/environ` vs session's FrontendAttrs.
- Last-resort: kprobe on `runc execve` capturing bundle path.
- Ambiguous attribution: emit with `ambiguous_vertices=[...]` rather
  than guess.

**Risks:**
- fanotify on cgroupfs has kernel-version requirements (fanotify on
  fsnotify_groups was added in 5.1; subdir monitoring works from 5.13).
  Mitigation: feature-check at agent start; fall back to inotify on
  older kernels with a slightly larger join window.
- The cmdline match is fragile if BuildKit changes the `sh -c` wrapper.
  Mitigation: integration test in CI against real BuildKit.

### Phase 3 — wire attribution into the egress event path (~3 days)

- In the ringbuf handler (`agentcore/enforcer/platform_linux.go`), where
  eBPF egress events are enriched, look up the cgroup_id in the
  buildkit registry (`LookupBuildKitBinding`).
- If found, populate the `BuildStep` field on the outgoing Violation.
- If not found (egress wasn't from a buildkit cgroup), leave unset —
  the field is optional.

**Risks:** none significant; this is a small enrichment step in the
existing event pipeline.

### Phase 4 — server-side ingest + dashboard surface (~1 week)

- Migration: add nullable columns to the violations table.
- `internal/api/readonly.go`: include build_step in egress view
  response.
- Svelte: render the chip + link to session history.
- E2E test: a recorded build → events flow through to the dashboard
  with correct attribution.

**Risks:** UI design choices (where to display the chip, what to do
when ambiguous) — best resolved by trying it and iterating.

### Phase 5 — operator config + docs (~3 days)

- New agent config keys: `BUILDKIT_GRPC_ADDR`,
  `BUILDKIT_GRPC_TLS_CA_FILE` (optional, for hardened deployments).
- Helm chart values for both agent and EE server.
- NetworkPolicy update in the operator's gitops repo.
- `docs/EVENT_FLOW.md` updated.
- New page in landing-page docs: "BuildKit step attribution".

### Phase 6 — upstream `SpecOpts.Hooks` PR (parallel, ~2 days)

Send a PR to `moby/buildkit` that adds a config option to the OCI
executor's `SpecOpts`, enabling external tools to inject runc hooks
via `buildkitd.toml`. If accepted, Pick B (Managed Runners) becomes
trivial later. Independent of this branch — separate PR, separate
review cycle.

**Total estimate:** 4–5 weeks of focused work; 6–7 weeks accounting
for parallel ops + customer-driven interrupts.

## Operating behaviour and trust limits

**The BuildKit egress attach is audit-only.** `BuildKitEgressAttach`
always loads the egress program in audit mode with empty allow/deny
maps: it observes and attributes, it never drops packets. The only
enforcement in this subsystem is the cgroup kill described below.

**Unbound events are reported, not dropped.** Egress from a watched
BuildKit cgroup that the join layer has not bound to a session and
vertex (no match yet, or none at all) is recorded with
`build_unattributed: true` and no `build_*` identity. Consumers must
not treat such rows as belonging to any build.

**Kill policy is opt-in.** Cgroups are killed (`cgroup.kill`) only when
the operator configured `requireCIMetadata` or at least one deny
pattern. With either on:

- a cgroup matched to an unauthorized session, or to a vertex matching a
  deny pattern, is killed;
- when several candidates match, the cgroup is killed if *any* candidate
  is unauthorized or matches a deny pattern;
- a cgroup that matches no vertex by the end of the match window
  (default 2s) is judged against *every* open session instead of being
  killed blindly. The candidate set is each pending `RUN` vertex of every
  non-completed session. The cgroup is killed if any open session is
  unauthorized or still a placeholder, if any pending vertex matches a
  deny pattern, or if the history watcher is disconnected (the registry
  cannot see new sessions). Otherwise it is bound as ambiguous over all
  candidates, or left unbound when there are none. This keeps containers
  that are not a `RUN` step, notably the `# syntax=` frontend gateway
  container that runs under the same cgroup parent, from being killed
  while every session is authorized, yet still kills them as soon as one
  unauthorized session could own them. With no policy configured a miss
  only leaves the cgroup unbound.

Matching tolerates the legitimate forms where the vertex text and the
process argv differ: exec-form `RUN ["npm","ci"]` (compared
element-wise), heredoc bodies (summary against the script's first line),
`$VAR` / `${VAR}` in the shell command (expanded in the vertex name, so
treated as wildcards), and the shell replacing itself with the last
command (`pip install` runs as `python3 /usr/local/bin/pip install`).
Each widening can only over-match, which produces an ambiguous candidate
set that the checks above treat fail-closed. A cgroup already bound is
not re-judged when a rescan re-reports it.

A session seen first through its Status stream (before its history
record) is a placeholder; the joiner keeps retrying instead of acting on
it until the history record supplies the session's attributes.

**The CI attributes are self-asserted.** `LEITWACHT_CI_*` values arrive as
build-args, which the build submitter controls. "Authorized" therefore
means only that the required build-arg keys are present and non-empty,
not that the build really belongs to the claimed project. Strong
binding of a build to a CI job needs a signed CI identity token
validated by the agent or server (future work). Likewise, nothing
kernel-visible ties a runc cgroup to a particular BuildKit session; when
several sessions run the same command the environ tiebreaker is
best-effort and the remainder is reported as ambiguous.

**Resilience.** The history subscriber backs off between reconnects and
closes sessions absent from a reconnect replay (the grace starts only
once the stream is established, and a later STARTED record reopens a
session); sessions with no activity are swept after
`LEITWACHT_CE_BUILDKIT_MAX_SESSION_AGE` (default 6h, measured from the
last registration or vertex update). The inotify watcher blocks in `poll(2)` (no busy loop),
rescans on queue overflow and re-establishes a lost watch. Bindings
record their cgroup path and are re-verified against the cgroup inode on
lookup, so a recycled inode never inherits a stale binding. The CE
daemon restarts the joiner with backoff if it exits.

**Logging.** Vertex names are Dockerfile text and can embed secrets, so
the agent logs only the vertex digest and a short hash of the name
(`vertex_name_hash`).

## What's explicitly out of scope for this branch

- **Pick B (runc wrapper)** — deferred to "Managed Runners launch"
  milestone. Same `BuildStepAttribution` proto; different join
  mechanism.
- **Pick C (fork)** — deliberately not pursued. See "Architectural
  choice" above.
- **BuildKit-in-CI-container topology** (ephemeral buildkitd in the
  same container as the CI job) — different agent architecture
  entirely; tracked separately if a customer demands it.
- **Cross-build identical-command disambiguation beyond ambiguous_vertices** —
  the honest fallback is sufficient for self-hosted single-tenant.
  Managed Runners gets Pick B's deterministic tuple before launch.

## Open questions (answered during implementation)

- Should the agent expose its build_step attribution as a Prometheus
  metric (e.g. `leitwacht_buildkit_vertex_egress_total{vertex_name=...,
  session_ref=...}`)? Probably yes — operators want it.
- What's the right TTL for the session registry after a build
  completes? Default 30s based on the existing buildkit drain window;
  may need tuning.
- If buildkitd is unreachable (NetworkPolicy not yet widened, daemon
  not yet running), does the agent fail loud or degrade silently to
  cgroup-only attribution? Probably loud at startup, silent
  thereafter — analogous to the existing DNS-proxy reachability
  assertion (leitwacht-3sn item 4).

## Related issues / references

- [moby/buildkit `control.proto`](https://github.com/moby/buildkit/blob/master/api/services/control/control.proto)
- [moby/buildkit `executor/runcexecutor/executor.go`](https://github.com/moby/buildkit/blob/master/executor/runcexecutor/executor.go)
- [moby/buildkit `executor/oci/spec.go`](https://github.com/moby/buildkit/blob/master/executor/oci/spec.go)
- [moby/buildkit history API #2711](https://github.com/docker/buildx/issues/2711)
- Beads tracking: `leitwacht-3sn` (original feature request)
