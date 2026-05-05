# leitwacht-agent-ce Helm chart

Deploys the leitwacht Community Edition agent as a privileged DaemonSet.
The agent attaches eBPF + nftables + an in-netns DNS proxy on every
GitLab Runner container and enforces egress according to the YAML rules
mounted into the pod.

## Quickstart

```sh
# Resolve your cluster DNS Service ClusterIP first.
KUBE_DNS_IP=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')

helm install leitwacht-ce ./ce/helm/agent-ce \
  -n leitwacht --create-namespace \
  --set-file rules=examples/rules.yaml \
  --set "dnsUpstream=${KUBE_DNS_IP}:53"
```

`dnsUpstream` is required — `helm install` fails fast if it isn't set.
The agent's in-netns DNS proxy forwards queries from runner containers
to whatever resolver you point this at. Use your cluster CoreDNS so
`*.svc.cluster.local` keeps working and queries don't leak to public
resolvers.

## Values

See [`values.yaml`](values.yaml) for the full set; the most important
settings are:

| Key                       | What it does                                          |
| ------------------------- | ----------------------------------------------------- |
| `rules`                   | Inline YAML for the rule ConfigMap.                   |
| `runtime`                 | `containerd` or `docker`.                             |
| `defaultAction`           | Fallback action when no scope matches.                |
| `scope.label`             | Pod label that selects a scope (`leitwacht.eu/scope`).|
| `sinks.prometheus.enabled`| Expose `/metrics` (default true).                     |
| `sinks.webhook.url`       | Optional outbound webhook for reports.                |

## Caveats

- The DaemonSet runs **privileged**. eBPF and nftables in a Pod
  Security Standards "restricted" namespace are not yet supported.
- The agent expects to mount the host's containerd socket and
  `/sys/fs/bpf`, `/sys/fs/cgroup`. On Talos this requires the relevant
  service patches; consult the upstream docs.
- Hot-reloading the rules ConfigMap takes effect within a few seconds
  thanks to fsnotify; no pod restart is needed.
