# Integration test runner

`run.sh` is a top-level driver that exercises both layers of the test
suite end-to-end on a dedicated Linux box:

- **CE e2e** — `tests/e2e/run.sh` (four cases against real Docker
  containers: allow/block, hot-reload, scope-label, webhook sink)
- **agentcore enforcer integration** — `go test -tags='integration linux'
  ./agentcore/enforcer/...` (real eBPF + nftables + containerd)

Plus pre/post-flight phases that start Docker, toggle SELinux to
Permissive (and restore it), check kernel logs for BPF/nft/SELinux
denials, and clean up leftover containers and nftables tables.

## Requirements

- Linux x86_64, kernel ≥ 5.15
- `root` (eBPF + nftables)
- `go` ≥ 1.27
- `docker`, `jq`, `curl`, `python3`
- (optional) `containerd` and `ctr` for the agentcore phase

## Running

```sh
sudo bash tests/integration/run.sh                  # everything (~5 min)
sudo bash tests/integration/run.sh ce-only          # CE e2e only (~2 min)
sudo bash tests/integration/run.sh agentcore-only   # agentcore enforcer only

# Or via the Makefile:
sudo -E make integration-suite
```

The script resolves the repo root from its own location; clone the
repo anywhere and the runner finds itself.

## Output

Every phase tees stdout + stderr to
`/tmp/leitwacht-integration-<timestamp>/<phase>.log`. The CE e2e
sub-runner preserves its sandbox under `e2e-sandbox/<case>/` for any
agent log + metrics snapshot you need to inspect. A `SUMMARY.txt`
(ANSI-stripped) is written at the end.

The runner exits non-zero if any non-cleanup phase failed, so it can
be wired into CI:

```sh
sudo bash tests/integration/run.sh && echo "all green" || exit 1
```

## What it does NOT do

- Build container images. Use `make docker-agent-ce` separately.
- Test the Helm chart on a real cluster. Use `helm install` against
  a kind / k3s / minikube cluster manually.
- Run on macOS or Windows. eBPF needs Linux.
