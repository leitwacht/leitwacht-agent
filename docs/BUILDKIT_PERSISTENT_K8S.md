# BuildKit step attribution — persistent K8s buildkitd

Operator guide for deploying step-level egress attribution when buildkitd
is a long-lived K8s Deployment shared across many CI jobs.

If your buildkitd is one-pod-per-CI-job, you can skip this doc — the
defaults in [BUILDKIT_STEP_ATTRIBUTION.md](BUILDKIT_STEP_ATTRIBUTION.md)
work out of the box.

---

## What this configuration achieves

For each `docker buildx build` your CI runners send to buildkitd:

- The egress agent sees every RUN step's network traffic and tags it
  with the BuildKit session ref, the LLB vertex digest, and the
  Dockerfile RUN string.
- Each tagged egress event also carries the CI job's identity
  (`project_path`, `job_id`, `pipeline_id`, ...), routed by the CI
  runner injecting `--build-arg LEITWACHT_CI_*=...` at buildx
  invocation time.
- One buildkitd flush in the agent produces N reports on the wire,
  one per CI job, each carrying its own report-level identity.
- (Optional) Sessions that didn't supply the required CI metadata
  are killed at runc-create via `cgroup.kill`.

## Trust model

This configuration assumes **one buildkitd Deployment serves one
leitwacht org**. Anyone who can submit a `Solve` to that buildkitd
can submit a build claiming any project path; the agent stamps the
claim onto egress events.

What stops cross-project spoofing inside the same org is the
**server-side JWT-strict mode**. When the CI runner sends a
`ci_job_jwt` (the GitLab OIDC token) with the violation report, the
server's per-row attribution path requires `BuildStepAttribution
.project_path` to match the JWT's `project_path` claim. A buildkitd
session that declares `LEITWACHT_CI_PROJECT_PATH=foo` but whose
report carries a JWT signed for project `bar` has its per-row
override rejected — the row falls back to the report-level identity
(also JWT-authoritative). This closes the same-org spoof window the
earlier trust-model copy flagged as a follow-on.

Mode summary:

| Auth path the report takes | Per-row `project_path` override |
| --- | --- |
| Verified `ci_job_jwt` (happy path) | Must equal JWT `project_path`; else rejected |
| Env-trust (no JWT, JWKS-fallback) | Allowed if it resolves under the same org |

Env-trust only kicks in for legacy CE agents and during JWKS
transients; everything else routes through strict mode.

## Operator setup

### 1. CI metadata reaches buildkitd

The CI runner must pass CI environment variables as buildx build-args
prefixed `LEITWACHT_CI_*`. BuildKit propagates these to
`SolveRequest.FrontendAttrs`, which the agent reads off
`Control.ListenBuildHistory`.

Required and optional keys:

| build-arg key                       | Required? | Maps to violation field |
| ----------------------------------- | --------- | ----------------------- |
| `LEITWACHT_CI_PROJECT_PATH`         | yes       | `project_path`          |
| `LEITWACHT_CI_JOB_ID`               | strongly recommended | `job_id`     |
| `LEITWACHT_CI_PIPELINE_ID`          | optional  | `pipeline_id`           |
| `LEITWACHT_CI_JOB_NAME`             | optional  | `job_name`              |
| `LEITWACHT_CI_JOB_STAGE`            | optional  | `job_stage`             |
| `LEITWACHT_CI_GIT_REF`              | optional  | `git_ref`               |
| `LEITWACHT_CI_JOB_URL`              | optional  | `job_url`               |

The `LEITWACHT_CI_*` namespace is reserved — the agent reads no other
build-arg prefixes for attribution.

### 2. Pass the metadata from your CI runner

#### Option A — `leitwacht-buildx` wrapper (recommended)

Drop the wrapper into a build base image:

```bash
curl -fsSL https://gitlab.com/leitwacht/leitwacht-agent/-/raw/main/tools/leitwacht-buildx \
  -o /usr/local/bin/leitwacht-buildx
chmod +x /usr/local/bin/leitwacht-buildx
```

Then change `docker buildx build` to `leitwacht-buildx build` in your
`.gitlab-ci.yml`:

```yaml
build:
  script:
    - leitwacht-buildx build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
```

The wrapper reads `CI_PROJECT_PATH`, `CI_JOB_ID`, etc. from the runner
environment and injects them as the `LEITWACHT_CI_*` build-args
before exec-ing the real `docker buildx`. No other changes.

#### Option B — hand-written build-args

If you'd rather not depend on the wrapper, the same effect with raw
`docker buildx`:

```yaml
build:
  script:
    - |
      docker buildx build \
        --build-arg LEITWACHT_CI_PROJECT_PATH="$CI_PROJECT_PATH" \
        --build-arg LEITWACHT_CI_JOB_ID="$CI_JOB_ID" \
        --build-arg LEITWACHT_CI_PIPELINE_ID="$CI_PIPELINE_ID" \
        --build-arg LEITWACHT_CI_JOB_NAME="$CI_JOB_NAME" \
        --build-arg LEITWACHT_CI_JOB_STAGE="$CI_JOB_STAGE" \
        --build-arg LEITWACHT_CI_GIT_REF="$CI_COMMIT_REF_NAME" \
        --build-arg LEITWACHT_CI_JOB_URL="$CI_JOB_URL" \
        -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
```

### 3. Agent reaches buildkitd

The agent subscribes to buildkitd's Control gRPC and watches its
cgroup tree. Both pieces need addressing.

`values.yaml`:

```yaml
buildkit:
  # buildkitd Control gRPC address. Empty disables BuildKit attribution.
  grpcAddr: tcp://buildkitd.buildkitd.svc:1234

  # Cgroup parent paths to watch for RUN-container creates. Glob
  # patterns expand at startup (one `*` per directory level). Find
  # the right shape for your cluster by inspecting the buildkitd
  # pod's cgroup tree once with `kubectl exec`:
  #   /sys/fs/cgroup/kubepods.slice/.../cri-containerd-<sandbox>.scope/buildkit/<runc-id>/
  cgroupPaths:
    - /sys/fs/cgroup/kubepods.slice/*/*/buildkit
```

**Dedicated parents only.** Each path must be a cgroup dedicated to buildkitd's RUN cgroups: the datapath treats every descendant as a build step, so the pre-bind SYN hold and enforcement apply to everything under it. Never point it at a parent that also holds other workloads.

Make sure your buildkitd pod's NetworkPolicy allows ingress on its
Control gRPC port from the agent's namespace. If your buildkitd runs
under a NetworkPolicy that restricts ingress to specific namespaces,
add the agent namespace to that allow-list.

### 4. (Optional) Hard policy: require attribution

By default the agent observes sessions even when CI metadata is
absent (they fall through to the buildkitd pod's container labels for
attribution — useful during rollout while not all pipelines are
wrapped).

To enforce that every Solve carry the required metadata or be killed
before it can do egress:

```yaml
buildkit:
  requireCIMetadata: true
  requiredAttrs:
    - LEITWACHT_CI_PROJECT_PATH
    - LEITWACHT_CI_JOB_ID
```

Sessions whose `FrontendAttrs` lack any listed key are marked
unauthorized. When the join layer sees their first RUN cgroup, it
writes `1` to `<cgroup>/cgroup.kill` — every process in that cgroup
SIGKILLs atomically, BuildKit propagates the failure to the buildx
client, the CI runner sees a clear error.

Roll out in two phases: start with `requireCIMetadata: false` while
you wrap your pipelines, then flip to `true` once the
`leitwacht_buildkit_session_attribution_total{result="no_session_meta"}`
metric stays flat.

### 5. (Optional) Domain rules for RUN steps: the build DNS proxy

IP/CIDR rules reach RUN steps through the egress filter. Domain (fqdn)
rules need name resolution to pass through the agent, which is what the
build DNS proxy does. It is off by default
(`buildkit.dnsProxy.enabled`, `LEITWACHT_CE_BUILDKIT_DNS_PROXY=true`);
without it, shadow/enforce policies with domain allow rules log an Error
once per policy version and rows carry `fqdn_rules_inactive`.

> **Read before enabling enforce.** With the proxy on, every name a RUN
> step resolves is judged by fqdn rules. Names that were only reachable
> through IP/CIDR rules or trusted networks (registry mirrors, `*.svc`
> names) are **sinkholed in enforce mode** unless an fqdn allow rule names
> them. Run in shadow first and add fqdn allows for every
> `dns_would_block` name.

How it works, and what you do **not** have to change:

- RUN steps of a default-network buildkitd share the buildkitd pod's
  network namespace and resolve through the cluster DNS. BuildKit removes
  loopback nameservers from RUN steps' `resolv.conf`, so overriding the
  resolver cannot reach them. The agent therefore leaves `resolv.conf` and
  `buildkitd.toml` alone and redirects instead: cgroup `sock_addr`
  programs (`connect4`, `sendmsg4`, `recvmsg4`) attached at the
  `cgroupPaths` rewrite UDP/TCP port-53 destinations of RUN cgroups to a
  proxy the agent binds inside the buildkitd netns
  (`127.0.0.153:15354` by default), and rewrite the source of UDP replies
  back to the address the step asked, so every resolver accepts them.
- The agent finds that netns from a live process inside a RUN cgroup
  under `cgroupPaths` (they share buildkitd's netns in host mode; the
  agent needs `hostPID`, which the chart sets). A process name is never
  trusted alone, since CI jobs control theirs; set
  `buildkit.dnsProxy.procCgroup` (a substring of buildkitd's cgroup path)
  to let the proxy bind before the first RUN step (a full pod UID or an
  absolute cgroup path; it breaks when the pod is recreated unless
  updated, so prefer leaving it unset). The redirect turns on only after
  a RUN process was seen in the proxy's netns and then **stays on between
  steps** (the proxy's sockets keep the netns alive); a RUN process that
  proves a different netns alone is treated as a buildkitd restart and
  the proxy rebinds. RUN processes in several netns at once, or a netns
  that changes every step, latch the redirect off for 10 minutes. The
  redirect programs also check the socket's netns in the kernel, so
  sockets in other netns are never rewritten. Until a trusted netns is
  known (the first build after an agent or buildkitd start) domain rules
  are not enforced. The agent watches the proxy's serving goroutines: if
  one dies the redirect is cleared first (DNS fails open to the upstream)
  and the proxy is rebound. When buildkitd
  restarts into a new pod netns the proxy is rebound. While it is not
  bound the redirect is off, DNS goes straight to `dnsUpstream` (the
  port-53 pin allows it), build rows of policies with domain rules are
  flagged `fqdn_rules_inactive`, and the agent logs why. Builds never
  break because the proxy is down.
- Each query is attributed to its RUN cgroup (the DNS PID tracker records
  every task below a BuildKit parent against its RUN cgroup) and answered
  by that step's policy: **enforce**: allowed names are resolved and their
  addresses added to the step's allow set (ports from the rule, 443/80
  when it has none); denied names get the rule's resolution (sinkhole or
  NXDOMAIN) and names no rule matches get the sinkhole; **shadow**: every
  name is answered normally and would-be denials are recorded as
  `dns_would_block`; **audit**, unattributed or ambiguous steps and
  queries from outside any RUN cgroup: answered normally, recorded as
  `dns_observed`.
- While an enforce policy is in play, the first name a still-unbound RUN
  step asks is held until the step is bound or the join deadline
  (2 s) passes, then answered per policy (or normally when it was never
  bound). On a policy update, names a step already resolved are carried
  into the new policy when they still match an allow rule, so builds do
  not stall on a re-resolve.
- Rows whose address the same RUN step resolved through the proxy carry
  that `domain` (`domain_source = build_dns_proxy`); DNS activity of bound
  steps carries `build_project_path`, `build_job_name` and `policy_key`.
- While the proxy is on, port 53 from RUN steps to anything but the proxy
  is dropped (enforce) or recorded `would_block` (shadow): other
  resolvers, v4-mapped addresses on IPv6 sockets and raw sockets cannot
  bypass it. The flag is cleared before the redirect is detached.
- One RUN step cannot starve the others: per step, at most 8 held and 32
  in-flight queries and about 200 queries/s; over the limit that step gets
  REFUSED. A step whose hold timed out and which binds later has the names
  it already resolved re-seeded against its policy.
- Seeded addresses have no TTL: they stay until evicted (LRU), as for job
  pods.
- Rows' `fqdn_rules_inactive` reflects whether the proxy was up when the
  row was recorded, not when it was flushed.
- `dnsUpstream` must be the resolver the RUN steps use; the proxy
  forwards to it.

Load note: every RUN-step name lookup that is not served from the proxy's
cache becomes a query from the agent to `dnsUpstream` (the cluster DNS), so
expect the cluster DNS to see the builds' full lookup rate; size its
replicas accordingly. The proxy bounds the damage a single tenant can do:
per step 32 in-flight queries and about 1000 queries/s, per project 64
in-flight, out of the proxy's shared 256. At least four projects acting
together are needed to exhaust the shared budget.

Liveness: every 5 s the agent queries the proxy through a socket inside its
own netns; if it does not answer, the redirect is cleared first (DNS fails
open to the upstream), an Error is logged and the proxy is rebound at the
next RUN step. A RUN step that moves into another netns (`unshare -n`) does
not cause a rebind while processes remain in the bound netns; only a
netns with no process left (a buildkitd restart) is replaced.

Kernel note: the port-53 bypass pin uses `bpf_get_netns_cookie` in
cgroup_skb programs. On kernels without it the agent loads an object
variant that never references the helper and logs a Warn; the bypass pin
is then only the upstream-only port-53 pin (this variant has not yet been
verified on an older kernel), so a v4-mapped or raw-socket
query to the configured upstream is not caught. Security note: a RUN step
granted `security.insecure` can `unshare -n`/escape cgroups and is outside
this enforcement (the agent cannot see it).

Limits: the RUN steps must share buildkitd's netns (BuildKit's default
host network mode). With a CNI/bridge-mode buildkitd each RUN step has its
own netns; the agent detects a RUN step outside the proxy's netns, turns
the redirect off and logs an Error, and domain rules stay inactive (IP
rules still apply). Daemon-side egress (`ADD <url>`, git contexts, cache
import/export, image pulls) is not RUN-cgroup egress and is not covered.

## Operations

### Verifying attribution end-to-end

Run a build through your wrapped CI runner. Wait for the bucket flush
(default 5m). The agent's NDJSON output (or webhook payload, or
ClickHouse query) should show violations with both:

- `build_session_ref`, `build_vertex_digest`, `build_vertex_name`
- `project_path` matching your `CI_PROJECT_PATH`,
  `job_id` matching your `CI_JOB_ID`

### Metrics

| Metric                                                | What it counts                                                       |
| ----------------------------------------------------- | -------------------------------------------------------------------- |
| `leitwacht_buildkit_session_attribution_total{...}`   | Per-session outcomes: `attributed`, `unattributed`, `ambiguous`      |
| `leitwacht_buildkit_session_killed_total{reason=...}` | Sessions killed by the kill-switch                                   |

A persistent `unattributed` count means a CI runner skipped the
build-args. A persistent `killed` count means a CI runner skipped
them under `requireCIMetadata: true`.

### Known limitations

- Glob expansion happens once at agent startup. If buildkitd's pod
  UID changes (pod restart), the agent currently needs a restart too.
- Identical RUN strings across concurrent Solve sessions surface as
  `ambiguous` with the candidate list rather than guessing — by
  design (see the design memo's "How parallelism is handled" section).
- DNS query attribution at the per-RUN level still attributes to the
  buildkitd pod, not the RUN sub-cgroup, until the cgroup-join layer
  also registers RUN cgroups in the DNS PID tracker BPF map. Packet
  attribution (the common case) is unaffected.
