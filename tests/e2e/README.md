# CE end-to-end tests

`run.sh` boots `agent-ce` against a generated `rules.yaml`, drives real
Docker containers through it, and asserts on the resulting NDJSON
stream + Prometheus counters.

## Requirements

- Linux x86_64
- Kernel ≥ 5.15 (eBPF CO-RE + BPF LSM bits the agent uses)
- Docker daemon running and reachable
- `root` (eBPF + nftables; the agent itself drops nothing)
- `go` ≥ 1.26 in `PATH`
- `curl`, `jq`, `python3` (used by the webhook case)

## Running

```sh
sudo -E ./tests/e2e/run.sh                    # all cases
sudo -E ./tests/e2e/run.sh allow_block        # one case
KEEP_LOGS=1 sudo -E ./tests/e2e/run.sh        # preserve sandbox at $WORK
LOG_LEVEL=debug sudo -E ./tests/e2e/run.sh    # more verbose agent logs
```

## What each case proves

| Case            | Asserts                                                                           |
| --------------- | --------------------------------------------------------------------------------- |
| `allow_block`   | Default-block scope blocks `httpbin.org` (a real reachable host, so any failure is unambiguously enforcement); allow rule lets `github.com` through; violation NDJSON appears with the right `project_path`/`hostname`; `leitwacht_ce_violations_total` counter increments. |
| `hot_reload`    | Editing `rules.yaml` while the agent is running flips a previously-allowed destination to blocked, with no agent restart. Tails the agent log for the `rules reloaded` line. |
| `scope_label`   | A container with `leitwacht.eu/scope=trusted` gets the `trusted` scope's allow-by-default rules even though `CI_PROJECT_PATH` differs from the scope name. Validates the scope-label plumbing in the watcher. |
| `webhook_sink`  | Spawns a tiny Python webhook receiver, points the agent at it via `LEITWACHT_CE_WEBHOOK_URL`, and confirms a `violation_report` JSON envelope is POSTed with the right shape. |

## Required container label

Every test container is launched with
`--label com.gitlab.gitlab-runner.managed=true`. The agent **only
watches** containers carrying this label — without it, no events fire
and the agent appears to be doing nothing. Mirror this when you run
ad-hoc curls against a leitwacht-protected host.

## What this does **not** test

- The honeypot LSM hook (run separately on a host with BPF LSM enabled).
- Multi-node / DaemonSet behaviour (covered by Helm-chart tests).
- IPv6 egress (env-tagged TODO; the YAML schema accepts IPv6 CIDRs but
  the smoke harness only exercises IPv4).

## Debugging

If a case fails, the harness preserves the agent log when run with
`KEEP_LOGS=1`. Useful one-liners:

```sh
# Agent-side NDJSON
jq -c 'select(.type=="violation_report")' "$WORK/<case>/agent.log"

# All metrics with the leitwacht_ce_ prefix
curl -fsS http://127.0.0.1:19090/metrics | grep ^leitwacht_ce_

# Live tail
tail -f "$WORK/<case>/agent.log"
```
