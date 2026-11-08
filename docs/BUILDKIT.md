# BuildKit: secure builder setup with Leitwacht

Operator guide for running a shared, persistent `buildkitd` (for example a
Deployment in Kubernetes serving many GitLab CI jobs) under Leitwacht
observation and, in the Enterprise edition, enforcement.

If your buildkitd is one pod per CI job, most of this guide does not apply.
Whether such a per-job builder, or a builder nested in a job container, is
covered as ordinary CI container egress depends on how it is run; that is
untested.

Related documents:

- [BUILDKIT_STEP_ATTRIBUTION.md](BUILDKIT_STEP_ATTRIBUTION.md): original
  design memo (historical; read this guide for current behaviour).
- [EVENT_FLOW.md](EVENT_FLOW.md): the agent's event loop.
- Enterprise per-project enforcement, storage and advisories:
  `docs/BUILDKIT_ENFORCEMENT.md` in the `leitwacht` repository.

---

## 1. What you get

For `RUN` steps executed by a persistent buildkitd, the agent observes
network egress at the kernel (eBPF `cgroup_skb` on each RUN step's cgroup)
and ties each connection to the CI job and project that submitted the
build.

- **Egress detection for RUN steps.** Every outbound connection of a RUN
  step is recorded (IPv4; see limitations).
- **Attribution to a CI job and project.** Priority order: project
  first, job second, Dockerfile step third. The per-step label
  (`build_vertex_name`, for example `[stage 2/5] RUN npm ci`) is best
  effort. When the agent cannot tell which build owns a step it says so
  (ambiguous or unattributed) and never picks one job at random.
- **Blocking (Enterprise edition, and CE through YAML rules).** The
  project's rules are applied to RUN steps in `shadow` (record
  `would_block`) or `enforce` (drop) mode.
- **Build DNS proxy (opt-in).** Domain (fqdn) rules need name resolution
  to pass through the agent. The proxy provides that for RUN steps.
- **Fail-open by default.** A step that cannot be tied to exactly one
  project runs in audit: reported, not blocked, not killed. The simplest
  way to land there is to omit the `LEITWACHT_CI_*` build-args (see 4.4
  and 7.6). Fail-closed behaviour is opt-in and has gaps.

What it is not: it does not verify who submitted a build (section 7), does
not cover daemon-side fetches (`ADD <url>`, git contexts, image pulls,
cache import/export), and does not isolate tenants from each other.

---

## 2. How it works

```
 CI job                          buildkitd pod                   Agent (DaemonSet)
 ------                          -------------                   -----------------
 buildx / buildctl
  --build-arg LEITWACHT_CI_*  -->  Solve session
                                   (FrontendAttrs carry          1. ListenBuildHistory +
                                    build-arg:LEITWACHT_CI_*)  <-   Status over gRPC:
                                                                    session -> vertices
                                   runc creates RUN cgroup       2. inotify on the cgroup
                                   .../buildkit/<id>/        ---->   parent: new cgroup
                                                                 3. join: first PID's argv
                                                                    == vertex RUN command
                                                                 4. cgroup_skb egress filter
                                                                    on RUN cgroups -> events
                                                                 5. flush: resolve to job /
                                                                    project, report
```

1. The CI side injects `LEITWACHT_CI_*` build-args (section 5.1). BuildKit
   records them as session metadata (`FrontendAttrs`, key
   `build-arg:<NAME>`).
2. The agent connects to buildkitd's Control gRPC (`grpcAddr`),
   subscribes to `ListenBuildHistory(ActiveOnly=true)` and, per active
   build, to `Status`. This yields sessions and their RUN vertices.
3. The agent watches the buildkit cgroup parent(s) (`cgroupPaths`) with
   inotify. When a RUN container's cgroup appears, the joiner reads the
   first process's argv and matches it against the RUN command of pending
   vertices (whole-command equality after whitespace normalisation).
   Matching is retried for a short deferred-match window (2 s default).
4. An eBPF `cgroup_skb` egress program is attached at every watched
   parent. It treats every descendant cgroup as one RUN step, finds that
   level in the kernel and judges each connection.
5. At flush time (the agent's bucket interval) each row is resolved:
   linked to a vertex, inherited from a single open session, lifted to
   project level, or flagged unattributed (section 6).

Session state lives in memory. After an agent restart or a dropped gRPC
stream the watcher reconnects and the active-only history replay
re-registers in-flight builds.

---

## 3. Securing the buildkitd itself

Leitwacht watches egress. It does not make buildkitd safe. Anyone who can
submit a build to buildkitd runs arbitrary code in a RUN step and, in the
rootful reference setup, does so on a privileged pod. Treat the builder as
a security boundary of its own.

### 3.1 What is tested

The tested configuration is **rootful, privileged `moby/buildkit` v0.18
(`seccompProfile: RuntimeDefault`) in BuildKit's default host network
mode, on cgroup v2**. The reasons: RUN cgroups are created under a
cgroup parent the agent can watch from the host, and RUN steps share the
buildkitd pod's network namespace (needed for the DNS proxy).

**Rootless buildkitd is untested and unsupported by Leitwacht today.**
Its cgroup layout and network namespace differ, and the agent's
`cgroupPaths` and RUN-level detection assume the rootful layout. If the
layout does not match, the datapath runs in audit and rows carry
`degraded_reason: run_level_mismatch`. Rootless would reduce what a
malicious build can do to the node, so it is a worthwhile future
direction, but do not rely on it with Leitwacht yet.

### 3.2 Recommendations

| Area | Recommendation |
| --- | --- |
| Placement | Dedicated namespace and, if you can afford it, dedicated nodes. A privileged pod shares its node's kernel with everything else scheduled there. |
| Network ingress | NetworkPolicy allowing `:1234` only from the CI job namespace and the agent's namespace. Default-deny everything else. |
| Network egress | NetworkPolicy egress limited to your registries, mirrors and cluster DNS. Daemon-side fetches are outside Leitwacht's RUN-step coverage, so this is the control for them. |
| Authentication | See 3.3: the reference setup has no TLS. |
| Image | Pin the buildkitd image by digest, not by tag. |
| Secrets | Never pass secrets as `--build-arg`. Use `--secret` or SSH mounts. Build-args are session metadata: visible to anyone who can read build history, and to the Leitwacht agent. |
| Registry credentials | `buildctl` forwards the client's `~/.docker/config.json` over the session, so no credentials need to live on buildkitd. Use short-lived job tokens (for example the CI registry token) and write the config in the job, not in the image. |
| Cache | See 3.4. |
| Resources | Set CPU/memory limits on the pod and cap parallelism (`--oci-worker-max-parallelism`). Many simultaneous RUN steps raise the chance of join ambiguity (section 7.2). |
| Entitlements | Do not enable `security.insecure` or `network.host`. A step with `security.insecure` can leave its cgroup or network namespace and is outside enforcement. |
| Host access | The agent needs `hostPID` and a writable `/sys/fs/cgroup` mount (the shipped charts set both). buildkitd itself should not get `hostPID` or `hostNetwork`. |

### 3.3 Transport security: no TLS in the reference setup

buildkitd's TCP listener in the reference setup is plaintext and
unauthenticated. Consequences:

- Any pod that can reach `:1234` can run builds, **and can claim any CI
  identity** through the build-args. Leitwacht records what the session
  claims (section 7.1).
- NetworkPolicy is therefore your primary access control. Enforce it with
  a CNI that actually implements NetworkPolicy.

BuildKit supports mutual TLS (`buildkitd --tlscacert --tlscert --tlskey`,
and `buildctl --tlscacert --tlscert --tlskey` on the client). It is the
right control for the CI clients, but note the **current interaction with
the agent**: the agent dials buildkitd with plaintext gRPC credentials and
has no TLS configuration option today (`grpcAddr` accepts `tcp://host:port`
or `unix:///path` only). A TLS-only buildkitd listener will therefore
break the agent's subscription. Options, in order of preference:

1. Keep the TCP listener plaintext, restrict it with NetworkPolicy to the
   CI and agent namespaces, and accept the residual risk.
2. Give buildkitd two listeners (`--addr` can be repeated): a mutual-TLS
   TCP listener for CI clients and a unix socket for the agent, with the
   socket directory exposed to the agent pod through a `hostPath`
   volume and `grpcAddr: unix:///path/to/buildkitd.sock`. The shipped
   charts do not mount such a volume, and this combination is
   **untested**.

Agent TLS support for the Control connection is not implemented.

### 3.4 Cache sharing is a cross-tenant risk

A persistent buildkitd shares its layer and content cache across every
project that builds on it. One project can poison cache entries another
project later reuses, and a build can learn what is cached. Leitwacht does
not address this. Run one buildkitd per trust boundary (per team, or per
sensitivity tier), or keep tenants on separate cache namespaces, and do
not share a builder between projects that must not influence each other's
artifacts.

---

## 4. Agent-side configuration

BuildKit support is off until `grpcAddr` is set.

### 4.1 Settings

| Helm value (`buildkit.*`) | CE env (`LEITWACHT_CE_BUILDKIT_*`) | Default | Meaning |
| --- | --- | --- | --- |
| `grpcAddr` | `GRPC_ADDR` | empty (off) | buildkitd Control gRPC address, `tcp://host:port` or `unix:///path`. Plaintext. |
| `cgroupPaths` | `CGROUP_PATHS` (comma list) | none | Cgroup parents to watch. Globs (`*` per directory level, no `**`) are re-resolved in the background (on inotify events, with a 15 s poll as fallback), so a buildkitd pod restart is picked up without an agent restart, with a short delay (7.7). The resolver caps at 32 paths, but the datapath accepts **at most 8 parents**; more makes the attach fail. |
| `requireCIMetadata` | `REQUIRE_CI_METADATA` | `false` | Flag sessions lacking any of `requiredAttrs` (`build_flag: missing_ci_attribution`). See 4.4. |
| `requiredAttrs` | `REQUIRED_ATTRS` | `LEITWACHT_CI_PROJECT_PATH` | Plain build-arg names required when `requireCIMetadata` is on. |
| `killOnUnattributed` | `KILL_ON_UNATTRIBUTED` | `false` | Opt-in, effective only together with `requireCIMetadata` or a deny pattern: SIGKILLs RUN cgroups of unauthorized sessions and some other uncertain cases. Never kills an ambiguous step whose candidates are all authorized (4.4). |
| `denyVertexPatterns` | `DENY_VERTEX_PATTERNS` (comma list) | none | RE2 patterns matched against the vertex name. A match on a single exactly-linked vertex kills the RUN cgroup. Patterns are process-wide, not per project. |
| `enforcement` (CE chart only) | `ENFORCEMENT` | `audit` | `audit`, `shadow` or `enforce` for RUN steps whose project scope is `block`. The EE chart has no such key: the server sets it per project. |
| `disableCgroupAttach` | `DISABLE_CGROUP_ATTACH` | `false` | Track sessions but attach no eBPF program (no egress observation). |
| `maxSessionAge` | `MAX_SESSION_AGE` | `6h` | How long a session that never completed stays tracked. |
| `dnsProxy.enabled` | `DNS_PROXY` | `false` | Build DNS proxy (section 4.3). |
| `dnsProxy.process` | `DNS_PROC` | `buildkitd` | Process name used to locate buildkitd. Never trusted on its own. |
| `dnsProxy.procCgroup` (CE chart only) | `DNS_PROC_CGROUP` | empty | Buildkitd pod UID or absolute cgroup path, to bind the proxy before the first RUN step. Leave empty; it breaks when the pod is recreated. |
| `dnsProxy.listen` | `DNS_LISTEN` | `127.0.0.153:15354` | Proxy address inside the buildkitd network namespace. |

Related agent-wide settings that matter here: `dnsUpstream` (required; the
cluster resolver buildkitd's RUN steps use; at most 4 IPv4 upstreams are
supported), `trustedCIDRs` (destinations
such as registry mirrors that shadow/enforce must not judge) and
`bucketInterval` (flush interval). The EE chart uses the same `buildkit.*`
keys under `agent.` and plain env names (`BUILDKIT_GRPC_ADDR` and so on).

### 4.2 Choosing `cgroupPaths`

Each path must be a cgroup **dedicated** to buildkitd's RUN cgroups. The
datapath treats every descendant as a build step, so the pre-bind SYN hold
and enforcement apply to everything beneath it. Never point it at a parent
that also holds other workloads.

For a rootful buildkitd in Kubernetes the shape is typically
`/sys/fs/cgroup/kubepods.slice/*/*/buildkit`. Inspect the buildkitd pod's
cgroup tree once (`kubectl exec` into the pod and read `/proc/self/cgroup`)
and write the glob accordingly. A glob that matches nothing is retried; the
agent logs `buildkit cgroup glob matched zero paths` until buildkitd
creates the parent (it does so lazily, at the first RUN step).

### 4.3 Build DNS proxy prerequisites

IP/CIDR rules reach RUN steps through the egress filter. Domain rules
need the agent to see the names a step resolves. Enable the proxy only
once you have read this section; with it on, names that were previously
allowed only by IP or trusted-network rules (registry mirrors, `*.svc`
names) are **sinkholed in enforce mode** unless an fqdn allow rule names
them. Run `shadow` first and add an fqdn allow for every
`dns_would_block` name.

Prerequisites:

- **`hostPID: true` on the agent** (set in the shipped charts). The agent
  takes the proxy's network namespace from a live process inside a RUN
  cgroup under `cgroupPaths`; a process name alone is never trusted
  (CI jobs control theirs).
- **buildkitd in BuildKit's worker network mode `host`** (the default,
  `--oci-worker-net=host`; not Kubernetes `hostNetwork`). RUN steps must
  share the buildkitd pod's network namespace.
- **cgroup `sock_addr` support** (`connect4`, `sendmsg4`, `recvmsg4`
  programs at the watched parents) so port-53 traffic is redirected to
  the proxy without touching buildkitd's `resolv.conf`. If the redirect
  programs cannot attach, the proxy does not start and domain rules are
  not enforced (a Warn is logged).
- **`bpf_get_netns_cookie` for `cgroup_skb`** for the full DNS bypass
  pin (section 7.4 for the fallback).
- **`dnsUpstream` set to the resolver the RUN steps actually use.** The
  proxy forwards to it, and shadow/enforce allow port 53 only to it.
- Privileges: the EE agent chart drops all capabilities and adds
  `SYS_ADMIN`, `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_PTRACE` and `KILL`; the
  CE chart runs the agent `privileged: true`. Both mount a writable
  `/sys/fs/cgroup`.

Behaviour you can rely on:

- **Fail-open.** If the proxy dies or does not answer its 5-second
  self-check (a query through a probe socket opened inside the buildkitd
  netns), the
  redirect is cleared first, DNS goes straight to `dnsUpstream`, rows of
  policies with domain rules carry `fqdn_rules_inactive`, and the proxy is
  rebound at the next RUN step. Builds never break because the proxy is
  down.
- **Late binding.** Until a trusted network namespace is known (the first
  build after an agent or buildkitd start) domain rules are not enforced.
  RUN processes in several network namespaces at once, or a namespace that
  changes every step, latch the redirect off for 10 minutes.
- **Per-step answers.** `enforce`: allowed names resolve and their
  addresses join the step's allow set; denied names get the rule's
  resolution (sinkhole or NXDOMAIN); unmatched names get the sinkhole.
  `shadow`: everything resolves, would-be denials are recorded as
  `dns_would_block`. `audit`, unattributed and ambiguous steps: answered
  normally, recorded as `dns_observed`.
- **Bypass pin.** While the proxy is on, port 53 from RUN steps to
  anything but the proxy is dropped (enforce) or `would_block` (shadow).
- **Limits per step.** At most 8 held and 32 in-flight queries and about
  1000 queries/s (burst 2000); over the limit that step gets REFUSED. Per
  project, at most 64 in-flight queries out of the proxy's shared 256.
- **Load.** Every uncached RUN-step lookup becomes a query from the agent
  to `dnsUpstream`. Size cluster DNS for the builds' full lookup rate.
- **Seeded addresses have no TTL.** They stay until evicted (LRU), as for
  job pods.

### 4.4 Requiring CI metadata, and what "kill" means

`requireCIMetadata: true` does **not** by itself kill anything. A RUN step
of a session lacking the required build-args is flagged
`missing_ci_attribution` and left running in audit.

`killOnUnattributed: true` is an opt-in that only acts **when
`requireCIMetadata` or at least one deny pattern is also configured**
(the registry's "enforcement enabled" condition). With both set, the
agent SIGKILLs (`cgroup.kill`) RUN cgroups of unauthorized sessions, and
in the other uncertain cases (no match while the history stream is down,
an ambiguous step with an unauthorized or deny-matching candidate). Alone
it does nothing.

What this does **not** give you:

- **A build that omits the `LEITWACHT_CI_*` args is unattributed, and
  unattributed means audit only** (reported, not blocked), unless
  `requireCIMetadata` **and** `killOnUnattributed` are both on. This is
  the simplest bypass of enforcement, and it applies to any submitter who
  can reach buildkitd.
- Even when armed, an ambiguous step whose candidates are **all
  authorized** is never killed, so overlapping sessions with identical
  steps and valid-looking claims stay in audit (the forged-overlap bypass,
  7.6).
- A deny-pattern match on a single exactly-linked vertex always kills; it
  is explicit policy, independent of this flag.

**Downgrade side effect (kill off).** With `requireCIMetadata` (or any
deny pattern) on and `killOnUnattributed` off, any *open* unauthorized or
deny-matching session makes the agent distrust every argv match: all
concurrent steps get `build_flag: argv_untrusted`, and the policy binder
treats them as ambiguous, which means **audit**. One unwrapped build
therefore drops all concurrent builds on that buildkitd to audit while it
is open. With the kill flag on, those steps are killed instead. The
same state also covers, for up to 30 s, a session whose Status event
arrived before its history record; with the kill flag on, concurrent
legitimate steps can be killed during that window.

Recommended rollout: wrap pipelines with `requireCIMetadata: false`, watch
for `missing_ci_attribution` flags to stop, then decide whether fail-closed
is worth the risk of failing legitimate builds when attribution is
uncertain.

---

## 5. CI-side integration

### 5.1 Passing CI identity to buildkitd

Required: `LEITWACHT_CI_PROJECT_PATH`. Strongly recommended:
`LEITWACHT_CI_JOB_ID`. Optional: `LEITWACHT_CI_PIPELINE_ID`,
`LEITWACHT_CI_JOB_NAME`, `LEITWACHT_CI_JOB_STAGE`, `LEITWACHT_CI_GIT_REF`,
`LEITWACHT_CI_JOB_URL`. The `LEITWACHT_CI_*` namespace is the only one the
agent reads. The job name selects a per-job policy where one exists; the
project's default policy applies otherwise.

**Option A: the `leitwacht-buildx` wrapper** (for `docker buildx build`)

Pin a release tag and verify a checksum rather than fetching from `main`
(placeholders shown):

```bash
TAG="<release-tag>"
curl -fsSL "https://gitlab.com/leitwacht/leitwacht-agent/-/raw/${TAG}/tools/leitwacht-buildx" \
  -o /usr/local/bin/leitwacht-buildx
echo "<sha256-of-that-file>  /usr/local/bin/leitwacht-buildx" | sha256sum -c -
chmod +x /usr/local/bin/leitwacht-buildx
```

```yaml
build:
  script:
    - leitwacht-buildx build -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
```

The wrapper maps `CI_PROJECT_PATH`, `CI_JOB_ID`, `CI_PIPELINE_ID`,
`CI_JOB_NAME`, `CI_JOB_STAGE`, `CI_COMMIT_REF_NAME`, `CI_JOB_URL` and
`CI_PIPELINE_SOURCE` to build-args and execs `docker buildx`. Non-`build`
subcommands pass through. A `LEITWACHT_CI_*` build-arg you set yourself
wins. (`LEITWACHT_CI_PIPELINE_SOURCE` is injected but the agent does not
read it today.)

**Option B: `buildctl` against a remote buildkitd** (the pattern used for
this project's own image builds)

```yaml
.build_image:
  image:
    name: moby/buildkit:v0.18.2@sha256:<pin-by-digest>
    entrypoint: [""]
  variables:
    BUILDKITD_ADDR: "tcp://buildkitd.buildkit.svc:1234"
  script:
    - |
      set -eu
      # Build the argument list with "$@": job names and refs can contain
      # spaces, so never word-split a string of arguments.
      set --
      for pair in CI_PROJECT_PATH:LEITWACHT_CI_PROJECT_PATH \
                  CI_JOB_ID:LEITWACHT_CI_JOB_ID \
                  CI_PIPELINE_ID:LEITWACHT_CI_PIPELINE_ID \
                  CI_JOB_NAME:LEITWACHT_CI_JOB_NAME \
                  CI_JOB_STAGE:LEITWACHT_CI_JOB_STAGE \
                  CI_COMMIT_REF_NAME:LEITWACHT_CI_GIT_REF \
                  CI_JOB_URL:LEITWACHT_CI_JOB_URL; do
        src="${pair%%:*}"; dst="${pair##*:}"
        val="$(printenv "$src" || true)"
        if [ -n "$val" ]; then
          set -- "$@" --opt "build-arg:$dst=$val"
        fi
      done
      buildctl --addr "${BUILDKITD_ADDR}" build \
        --frontend dockerfile.v0 \
        --local context="${CI_PROJECT_DIR}" \
        --local dockerfile="${CI_PROJECT_DIR}" \
        "$@" \
        --output "type=image,name=${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA},push=true"
```

**Option C: hand-written `docker buildx` build-args**

```bash
docker buildx build \
  --build-arg LEITWACHT_CI_PROJECT_PATH="$CI_PROJECT_PATH" \
  --build-arg LEITWACHT_CI_JOB_ID="$CI_JOB_ID" \
  --build-arg LEITWACHT_CI_PIPELINE_ID="$CI_PIPELINE_ID" \
  --build-arg LEITWACHT_CI_JOB_NAME="$CI_JOB_NAME" \
  -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
```

A Dockerfile need not declare `ARG LEITWACHT_CI_*`: the agent reads the
session metadata, not the RUN environment.

### 5.2 Network access for the agent

The agent's namespace needs ingress to buildkitd's Control port
(NetworkPolicy allow-list; section 3.2).

### 5.3 Agent deployment

Use the CE chart (`ce/helm/agent-ce`) or the EE agent chart (in the
`leitwacht` repository). Minimal CE values:

```yaml
dnsUpstream: "<cluster-dns-ip>"
buildkit:
  grpcAddr: tcp://buildkitd.buildkit.svc:1234
  cgroupPaths:
    - /sys/fs/cgroup/kubepods.slice/*/*/buildkit
  requireCIMetadata: false
  enforcement: audit
```

Start in `audit`, confirm attribution (section 8), then move projects to
`shadow` and `enforce`.

---

## 6. Attribution outcomes

Every egress row from a RUN cgroup ends in one of these. The outcome label
describes how the row is **filed**; the row's `enforcement_state` records
what the datapath actually did. `environ_tiebreak` never chooses between
projects.

| Outcome | Row carries | How it arises | What it means for policy |
| --- | --- | --- | --- |
| **Linked to step** | `build_session_ref`, `build_vertex_digest`, `build_vertex_name`, project, job id and other `build_*` identity | The RUN step's argv matched exactly one pending vertex (binding strength `exact_argv`, or `environ_tiebreak`). | Policy of the claimed project and job name (the project default list if the job has none). Enforced in shadow/enforce (an `environ_tiebreak` link across projects, or an `argv_untrusted` link, runs in audit). |
| **Job-level (session)** | Session ref, project, job id; no vertex | Join found no vertex, but all builds open at event time share one CI identity. | Same as above. |
| **Project-level (ambiguous)** | `build_ambiguous: true`, `build_project_path`, no job id, sorted `build_ambiguous_job_ids` (up to 16), common pipeline id if any | Several builds overlap and the step cannot be pinned to one, but every candidate belongs to one project (agent v0.14.1 and later). | Candidates from one project: the project's default policy applies (enforcement is unchanged by the lift). In the EE server these rows are stored under the project as job `buildkit-ambiguous` and raise an advisory. |
| **Ambiguous across projects** | `build_ambiguous: true`, no project | Candidates belong to different projects, or one lacks a project or job id. | Filed without a project. For enforcement, candidates in different projects, or one without a project claim, run in audit (`enforcement_state: ambiguous_multi_project`). Candidates that share a project but lack a job id are still judged by that project's default policy. |
| **Unattributed** | `build_unattributed: true`, no project | No match and no session could be tied to the step. | Audit only (`enforcement_state: unattributed`). In EE: stored with project 0 under the reporting agent's org, advisory raised. |

Binding strengths, weakest last: `exact_argv`, `environ_tiebreak`,
`weak_tail`, `session_level`, `ambiguous`. Evidence from `weak_tail` (the
last simple command of a compound RUN) and `session_level` is treated as
forgeable: such rows are decided over all open sessions, not over their
own candidate list, and are never single-linked to a vertex.

Other row annotations:

- `enforcement_state`: `enforced`, `shadow`, `audit_project`,
  `pending_bind`, `ambiguous_multi_project`, `unattributed`,
  `degraded_capacity` (all 256 policy slots in use),
  `degraded_history` (history stream down), `policy_unavailable`,
  `degraded_level` (see `degraded_reason`, for example
  `run_level_mismatch`).
- `would_block`: the row passed but the bound policy would deny it
  (shadow, or traffic before the step was bound).
- `build_flag`: `missing_ci_attribution`, `deny_pattern_match`,
  `argv_untrusted`, `unmatched_under_policy`, `history_disconnected`.
- `binding_verified`: always `false` today (section 7.1).
- Actions you will see: `packet_observed`, `packet_allowed`,
  `packet_dropped`, `would_block`, `sinkhole_hit`, `dns_bypass_dropped`,
  `syn_held`; DNS rows use `dns_observed`, `dns_would_block` and friends.

### 6.1 Pre-bind SYN hold

A RUN step has no policy for the first few tens of milliseconds, until
the join binds it. While any enforce-mode policy is in play, the datapath
drops the TCP SYNs of a not-yet-bound RUN cgroup (`syn_held`) so the
kernel's retransmit, about one second later, is judged by the bound
policy. The hold window is **2 seconds** from the cgroup's first held SYN
(`DefaultSynHoldWindow`). After it, the step runs in audit and the
traffic passes, recorded. The hold is on only while some enforce policy
exists, so audit/shadow-only clusters never pay the latency.

---

## 7. Limitations

Read this before relying on the feature. These are properties of the
current code, not roadmap items.

### 7.1 Identity is an unverified claim

The CI identity comes from build-args that the submitter controls. The
agent flushes build rows itself, not on behalf of a CI job, so no
job-signed token (GitLab ID token) accompanies them; rows carry
`binding_verified: false`. Anyone who can reach buildkitd can claim any
project's identity, which has two effects: forged egress can be filed
under another project, and a malicious build can claim a project with a
more permissive policy. Mitigations today are access control (3.2, 3.3).
A verified binding (a nonce or token bound to the session) is not built.
Server-side checks limit the damage to the reporting org, with one
important exception: a **fully attributed claim (project plus job id) is
routed like any other env-trust CI report, and an unknown project path is
auto-created in the org**. A forged claim can therefore create projects.
Only project-lifted rows and per-row overrides refuse unknown or foreign
projects (see the EE document).

### 7.2 Concurrency degrades attribution

Joining a cgroup to a build relies on matching the step's command line to
a vertex. Overlapping builds that run **identical RUN commands** cannot be
told apart by that evidence. In that case the row loses job-level
attribution: it becomes project-level if all candidates share a project,
and unattributed or ambiguous across projects otherwise. On a
deliberately adversarial test fixture (many overlapping builds of
identical steps), job-level attribution was about 71% before project-level
lift was added and project-or-better about 92% after. This is a fixture
result, not a production guarantee; real pipelines with distinct steps
fare better, and highly parallel builds with common steps fare worse.

### 7.3 Per-step attribution is best effort

The step label comes from matching the RUN command. Shapes that do not
match whole-command equality (for example a `set -e;` prefix added by a
wrapper, or only the tail of a compound command matching) never link to a
step; tail-only matches are explicitly not trusted. The row keeps its job
or project identity where that is determinable, without a step label.

### 7.4 Platform and kernel

- **Linux, x86_64, cgroup v2 only.** arm64 and cgroup v1 are not
  supported. IPv4 only for policy: for a bound step in `enforce`, IPv6
  egress is dropped; in `shadow` recorded as `would_block`; in `audit` it
  passes unrecorded.
- **Kernel 5.10 or newer** for shadow/enforce (cgroup_skb with spin locks
  and map-in-map). Audit-only observation has no stated minimum beyond
  the agent's own requirements.
- **`bpf_get_netns_cookie` for `cgroup_skb`.** The agent probes for it at
  start. Without it the agent loads an object variant that never
  references the helper and logs a Warn; the DNS bypass pin then
  degrades to the upstream-only port-53 pin, so v4-mapped and raw-socket
  queries to the configured upstream are not caught. **That variant is
  untested on 6.1/6.6-era kernels**; test on your kernel before trusting
  domain enforcement there.
- **BPF LSM socket attribution.** The datapath shares the agent's
  `sock_attr` LSM program for packet attribution; if it cannot load, the
  agent logs `buildkit packet attribution unavailable`.

### 7.5 Network mode and DNS

- The DNS proxy requires buildkitd in BuildKit's worker network mode `host` and `hostPID` on
  the agent, and is opt-in.
- A buildkitd in CNI or bridge network mode gives each RUN step its own
  network namespace. The agent detects this, turns the redirect off and
  logs an Error: **IP rules still apply, domain rules do not**.
- Daemon-side egress (`ADD <url>`, git contexts, cache import/export,
  image pulls, registry pushes) is not RUN-step egress and is not
  covered.
- A RUN step granted `security.insecure` can escape its cgroup or network
  namespace and is outside enforcement.

### 7.6 Block mode and uncertainty

Under block mode, ambiguous-across-projects and unattributed egress is
**reported and audited, not killed**. Killing is opt-in and conditional
(`killOnUnattributed` together with `requireCIMetadata` or deny patterns,
4.4). Rationale: failing a legitimate build because attribution was
uncertain is worse than a recorded gap. The consequences:

- A build that omits the `LEITWACHT_CI_*` args is unattributed and
  escapes blocking unless `requireCIMetadata` and `killOnUnattributed`
  are both on.
- An attacker who can create overlapping sessions with identical RUN
  steps and well-formed claims makes steps ambiguous; even with the kill
  flag on, such a step is not killed when all candidates are authorized.
  It is still recorded.
- With `requireCIMetadata` (or deny patterns) on and the kill flag off,
  one open unwrapped or deny-matching session turns every concurrent
  step's match `argv_untrusted`, which the binder treats as ambiguous
  (audit). One bad build downgrades all concurrent builds (4.4).

The pre-bind SYN hold covers TCP only (IPv4 and IPv6 SYNs); UDP and other
traffic of a not-yet-bound step is not held and passes in audit. The
hold lasts at most 2 seconds (6.1).

### 7.7 Scope of enforcement

- **Per-project build-step deny patterns are not available.**
  `denyVertexPatterns` is agent-wide, and in the Enterprise edition
  server-distributed `build_vertex` deny rules also feed one process-wide
  set (the most recently fetched project's patterns replace the previous
  set). A TODO in the code tracks moving them into per-project policy.
- **Strict JWT mode and shared builders are currently incompatible
  (EE).** Under `jwt-required` mode the server refuses every report
  without a job token. Reports from a shared buildkitd never carry one,
  so **all** BuildKit reports (attributed, project-level and
  unattributed) are rejected and nothing is stored. Do not enable strict
  mode on an install that relies on this feature.
- **Multi-org installs (EE):** unattributed and ambiguous-across-projects
  build rows are dropped (counted, metadata logged) because the shared
  agent credential gives no stronger org binding than a hostname. See the
  EE document.
- **Other build tools.** This feature covers `buildkitd`. Builds by
  kaniko, buildah, or the classic Docker builder are not BuildKit
  sessions and get no step or session attribution here. If such a tool
  runs inside a CI job container, that container is covered as ordinary
  job egress, as any CI container; whether a given build tool's nested
  containers are covered is untested.
- **Cache poisoning and cross-tenant cache** are not addressed (3.4).
- **buildkitd pod recreation gap.** A recreated pod has a new cgroup
  path, and the parent cgroup is also created lazily, at the first RUN
  step. The agent watches, with inotify, the existing directories the
  `cgroupPaths` globs and literals live under (for a missing literal,
  its nearest existing ancestor) and re-resolves on a create event,
  coalescing bursts over about 50 ms. A path set that adds a directory
  (or replaces a vanished one with a new one, including a recreated
  inode) is applied at once: no removal debounce and no restart rate
  limit, so coverage normally resumes within about 1 to 2 s. Further
  additions are floored at one apply per 2 s (a throttled change is
  applied by a deferred re-resolve at the end of the floor), so a
  storm of new cgroups cannot cause unbounded restarts. The apply
  restarts the joiner and attach with the new set; the new attach
  starts before the old one is closed, so paths that stay in the set
  keep their eBPF coverage, while the joiner restarts briefly.
  Removal-only changes keep the protection against flapping: two
  consecutive 15 s timer polls must agree (events never count), and
  such restarts are rate limited (5 minutes, doubling up to 1 hour
  while consecutive); the surviving paths stay covered meanwhile. A
  failed apply (for example more than 8 resolved parents, which the
  datapath rejects) keeps the old generation and is retried with a
  doubling backoff that starts at the 2 s floor. The backoff resets on
  any successful apply and on any healthy poll. It holds back a repeat
  of the failed set and any set over 8 parents, but a set containing a
  genuinely new parent only waits for the 2 s floor. A failure is logged once
  per failure streak. When the resolved set exceeds the 32-path cap,
  paths already covered are kept in preference to new ones.
  **Remaining gap:**
  - If inotify is unavailable, dies, or cannot watch a directory
    (instance or watch limits), the agent logs a warning and falls back
    to the 15 s poll, so new parents are picked up after up to about
    15 s.
  - At most 256 directories are watched. Directories leading to
    currently resolved paths rank first; when the cap drops others, one
    warning is logged and those are poll-only.
  - A burst of additions inside the 2 s floor, or a failing apply in
    backoff, delays coverage for the new paths until the floor or
    backoff ends.
  - The joiner and attach restart on every apply. During the
    make-before-break overlap both attaches observe the same traffic,
    so violation rows can be duplicated. When the DNS proxy is enabled, the
    build DNS redirect is off until the new proxy rebinds (about
    0.5 s, or until the next RUN step if none is running).
  - Until a new parent is applied, RUN steps under it have **no eBPF
    program attached: no enforcement and not even audit rows**.
- **Restarts.** Session state is in memory. After an agent restart or a
  gRPC reconnect the active-only history replay restores in-flight
  sessions, but RUN steps that were already running during the gap may be
  unbound; how many is untested. The pre-bind hold and enforcement for new
  steps resume once the stream is up. While the history stream is down,
  new cgroups are not trusted to belong to a known session (audit,
  `degraded_history`).
- **Slots.** At most 256 distinct (project, job, policy version) slots are
  in use at once; beyond that steps run in audit
  (`degraded_capacity`).

---

## 8. Verifying it works

1. Run a wrapped build with a deliberate egress, for example
   `RUN curl -sS https://example.com`.
2. Wait for the bucket flush (the CE chart default is 5 minutes, the EE
   chart default 10 seconds).
3. In the agent's NDJSON output, webhook payload or the EE violations view
   look for a row with:
   - `build_session_ref`, `build_vertex_name` (`RUN curl ...`);
   - `build_project_path` equal to `CI_PROJECT_PATH` and `build_job_id`
     equal to `CI_JOB_ID`;
   - `enforcement_state` appropriate to your mode and `binding_strength`
     `exact_argv`.
4. Run two builds of the same project with identical steps concurrently
   to see the project-level ambiguous outcome: `build_ambiguous: true`,
   empty `build_job_id`, `build_ambiguous_job_ids` listing both jobs.
5. Run a build without the build-args to see an unattributed or
   `missing_ci_attribution` outcome, depending on your settings.

### Logs and metrics

There are **no BuildKit-specific Prometheus metrics**. CE exposes the
general `leitwacht_ce_violations_total{project_path,action}`,
`leitwacht_ce_dns_queries_total{project_path,action}` and
`leitwacht_ce_advisories_total{kind}`; BuildKit rows count toward them.
Use these log lines (structured, metadata only) for diagnosis:

| Log message | Meaning |
| --- | --- |
| `buildkit cgroup not attributed: no pending vertex matched before the join deadline` | A RUN cgroup could not be tied to a vertex. Fields: `pending_vertices`, `history_disconnected`, `suppressed_since_last` (the line is rate-limited). A steady stream means missing build-args, a command-matching problem or overlap. |
| `buildkit cgroup glob matched zero paths` | `cgroupPaths` does not match yet or at all. |
| `buildkit history stream ended` / `buildkit connect failed` | Control gRPC unreachable: NetworkPolicy, wrong `grpcAddr`, or a TLS-only listener (3.3). |
| `buildkit policy: no slot capacity; cgroup stays in audit` | Slot table full (7.7). |
| `buildkit dns proxy unbound; ...` / `... serving goroutine exited ...` | DNS proxy down; DNS is failing open. |
| `kernel lacks bpf_get_netns_cookie for cgroup_skb ...` | The reduced bypass pin is active (7.4). |
| `buildkit pre-bind SYN hold` (`enabled`) | The hold turned on or off with enforce policies. |

---

## 9. Checklist

- Builder in its own namespace; image pinned by digest; NetworkPolicy
  ingress limited to CI and agent namespaces, egress limited to what
  builds need.
- No secrets in build-args; credentials via `--secret` and short-lived
  tokens.
- One buildkitd per trust boundary.
- `cgroupPaths` dedicated to RUN cgroups; verified against the pod's real
  cgroup tree.
- Pipelines wrapped; `missing_ci_attribution` flags at zero before any
  fail-closed setting.
- Rollout order: `audit`, then `shadow` (add fqdn allows for every
  `dns_would_block` if the DNS proxy is on), then `enforce`.
- You have read section 7 and accept the residual risks.
