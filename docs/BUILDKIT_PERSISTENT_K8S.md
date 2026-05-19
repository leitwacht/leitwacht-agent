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
