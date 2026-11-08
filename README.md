# leitwacht-agent

> <https://leitwacht.eu> — source of truth: <https://gitlab.com/leitwacht/leitwacht-agent>.
> Issues, MRs, and discussions live on GitLab.

> **Pre-1.0.** The 0.x series is pre-stable; minor releases may carry
> breaking changes to APIs, env-var names, helm `values.yaml` keys, and
> rule-file schema until 1.0 ships. Pin to image digests (not floating
> tags) in production. See [CHANGELOG.md](CHANGELOG.md) for upgrade notes.

The data-plane agent for the leitwacht GitLab Runner egress-control
system. eBPF + nftables + an in-netns DNS proxy attach to every CI
runner container and enforce egress policy. CE (this repo) reads its
rules from a local YAML file and is fully standalone — no backend, no
phone-home, no enrolment.

A separately-licensed Enterprise Edition
([gitlab.com/leitwacht/leitwacht](https://gitlab.com/leitwacht/leitwacht))
adds a managed control plane (rule-authoring UI, multi-tenancy, audit,
GitLab integration). The EE agent imports `agentcore/` from this repo
and replaces the YAML loader with a gRPC rule stream.

## Layout

```
agentcore/                   data-plane primitives (MPL-2.0)
  enforcer/                  eBPF + nftables + DNS proxy + LSM cred/proc_mem
  watcher/                   container-lifecycle event source (containerd, docker)
  handler/                   lifecycle handler — edition-neutral
  policy/                    ResolvedPolicy + Source interface + loader
  advisory/                  plain-Go advisory type + Sink interface
  violation/                 plain-Go violation reporting Sink interface
  wildcard/                  domain-pattern matching helpers
  version/                   build-version stamp (set via -ldflags)
  cmd/
    leitwacht-initc/          pod init container that gates entrypoints on agent attach

ce/                          Community Edition daemon (MPL-2.0)
  cmd/agent-ce/              the binary
  config/                    env-driven daemon settings
  ruleyaml/                  YAML rule loader + fsnotify hot-reload
  sinks/                     stdout NDJSON / Prometheus / webhook
  helm/agent-ce/             Helm chart
  SCHEMA.md                  YAML rule schema (v1)

examples/
  rules.yaml                 starter rule set

docs/
  EVENT_FLOW.md              watcher → handler → enforcer flow + tunables (with mermaid)
  BUILDKIT.md                BuildKit: secure builder setup, integration, limitations
```

## Container scope

leitwacht-agent only inspects containers carrying the GitLab Runner
managed label `com.gitlab.gitlab-runner.managed=true`. Containers
without this label — anything you spin up by hand, sidecars, application
workloads — are ignored entirely (no events, no enforcement, no
violations). This is deliberate: leitwacht is the data plane for **CI
runner** egress, and non-runner workloads should not be silently
intercepted. Non-Runner use cases are out of scope for v0.1.0.

## DNS configuration advisory

At attach the agent reads each container's `resolv.conf` (ndots and search
domains) and logs one `dns config observed` line with counts only. When the
configuration amplifies lookups (`ndots >= 3` with 2+ search domains) or
carries non-cluster search suffixes, CE emits a `dns_config` advisory on its
NDJSON / webhook / Prometheus sinks, with a `lower_ndots` or
`node_search_domains` recommendation. Details: `docs/EVENT_FLOW.md`.

## Known limitations (v0.1.0)

- **IPv4 only.** The eBPF programs and DNS proxy enforce on IPv4 traffic; IPv6 egress is dropped at the netns boundary regardless of policy. CI jobs that require IPv6 connectivity cannot use leitwacht enforcement until this is addressed.
- **Linux x86_64 only.** arm64 runners are not yet supported (CI ships amd64 images; arm64 follows once we have eBPF artefacts for that architecture).
- **GitLab Runner workloads only.** See "Container scope" above.

## Quickstart

```sh
# Build (CGO_ENABLED=0 lets non-Linux hosts cross-compile cleanly).
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...

# Container image
docker build -f Dockerfile.agent-ce -t leitwacht/agent-ce:dev .

# Helm install (Kubernetes). dnsUpstream is required — point it at your
# cluster DNS resolver, not a public one, so internal services keep
# resolving and queries don't leak.
KUBE_DNS_IP=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')
helm install leitwacht-ce ./ce/helm/agent-ce \
  -n leitwacht --create-namespace \
  --set-file rules=examples/rules.yaml \
  --set "dnsUpstream=${KUBE_DNS_IP}:53"
```

The full schema reference for `rules.yaml` lives in
[ce/SCHEMA.md](ce/SCHEMA.md).

## License

`agentcore/` and `ce/` are distributed under the Mozilla Public License
2.0 — see [LICENSE](LICENSE). MPL-2.0 is a file-level copyleft license:
you may use, modify, and redistribute these files in your own products
(commercial or otherwise), but any changes you make to MPL-2.0-licensed
files must be made available under the same license.

The Enterprise Edition backend at gitlab.com/leitwacht/leitwacht is
distributed under a different license. The two repositories are
co-developed by the same team.

## Contributing

Issues and merge requests on the canonical GitLab repo
(<https://gitlab.com/leitwacht/leitwacht-agent>). Security issues
should follow the process in [SECURITY.md](SECURITY.md). Workflow and
style notes are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Building

Linux only (eBPF + nftables): `GOOS=linux GOARCH=amd64 go build ./...`

The eBPF objects (`*_bpfel.o`) are committed because regenerating them
requires `clang` + kernel headers; CI builds rely on the committed
artefacts. To regenerate locally on Linux:

```sh
go generate ./agentcore/enforcer/
```
