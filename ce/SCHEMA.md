# CE rule YAML schema (v1)

`leitwacht-ce` reads its rules from a single YAML file
(default `/etc/leitwacht/rules.yaml`, override with
`LEITWACHT_CE_RULES_PATH`). The file is reloaded automatically when it
changes — bad reloads are logged and the previous good snapshot is
retained.

> **Container scope:** leitwacht only watches containers labelled
> `com.gitlab.gitlab-runner.managed=true`. Workloads without this
> label are never inspected and never produce violations. If you're
> testing CE outside of GitLab Runner, you must add this label
> manually (`docker run --label com.gitlab.gitlab-runner.managed=true …`)
> for the agent to see the container at all.

## Top-level

```yaml
schema_version: 1            # required, must be 1
scopes: [...]                # required, at least one entry
reserved_domains: [...]      # optional list of FQDNs the agent owns
```

## Scope

A scope is an operator-named group of rules. CE matches a running
container to a scope using the configured label
(`LEITWACHT_CE_SCOPE_LABEL`, default `leitwacht.eu/scope`) or env var
(`LEITWACHT_CE_SCOPE_ENV`, default `LEITWACHT_SCOPE`). If no match is
found, the scope named `default` is used as the fallback.

```yaml
scopes:
  - name: default            # required
    default_action: allow    # allow | block | audit
    job_actions:             # optional, override default_action per CI job
      build: block
      release: allow
    credwatch: enforce       # optional LSM mode: off | observe | enforce
    proc_mem: observe        # optional LSM mode: off | observe | enforce
    job_overrides:           # optional, per-CI-job LSM mode overrides
      detonate-sample:
        credwatch: observe
        proc_mem: observe
    rule_sets:               # required
      "":                    # "" is the catch-all rule list
        - pattern: github.com
          pattern_type: domain
          action: allow
    deny_ips:                # optional, IP/CIDR-only deny list
      - ip: 169.254.169.254  # AWS IMDS
        port: 80
```

### `default_action` values

| Value   | Meaning                                                |
| ------- | ------------------------------------------------------ |
| `allow` | Agent does not attach enforcement at all.              |
| `block` | Default-deny — only rules with `action: allow` get out. |
| `audit` | Default-allow but log every connection (no blocking). |

### `job_actions`

Optional per-CI-job overrides. Keys are CI job names (matched against
the container's `CI_JOB_NAME` env var); values are the same set as
`default_action`.

### `credwatch` / `proc_mem`

Optional scope-default mode for the two LSM detectors:

| Detector   | Watches for                                            |
| ---------- | ------------------------------------------------------ |
| `credwatch`| Reads of credential files (`~/.aws/credentials`, SSH keys, …). |
| `proc_mem` | Reads of another process's `/proc/<pid>/mem`.          |

| Mode      | Behaviour                                                 |
| --------- | --------------------------------------------------------- |
| `off`     | Detector not attached for the container — no monitoring.  |
| `observe` | Event is reported, but the workload is **not** killed. For detonation sandboxes where killing at first hit truncates the kill chain. |
| `enforce` | Event is reported **and** the container is killed.        |

These only take effect when the corresponding detector LSM is loaded
globally (`LEITWACHT_CE_CREDWATCH_ENABLED`,
`LEITWACHT_CE_PROC_MEM_ENABLED`). When the detector is loaded but a scope
omits the field, the mode defaults to `enforce` (matching the historical
"globally on = kill" behaviour). The per-container exemption labels
(`leitwacht.io/allow-cred-read`, `leitwacht.io/allow-proc-read`) still
apply on top and suppress events entirely for a marked container.

#### Path classes (credwatch)

Each credential path suffix falls in one class; precedence is exclude,
then report-only, then watched:

| Class       | Default paths | Behaviour |
| ----------- | ------------- | --------- |
| watched     | cloud credentials, SSH keys, kubeconfig, `.git-credentials`, vault tokens, ... | `enforce`: open denied (EPERM) and container killed. `observe`: event only. |
| report-only | `/.docker/config.json`, `/.npmrc`, `/.netrc`, `/.pypirc` | Event with `action_taken=reported`; the open is **always allowed** and the container is never killed, in every mode. Registry logins are normally read by package managers, so reads are reported rather than treated as theft. |
| exclude     | none | No event, no enforcement. |

Override with `LEITWACHT_CE_CREDWATCH_PATHS` (watched),
`LEITWACHT_CE_CREDWATCH_REPORT_ONLY_PATHS` (report-only) and
`LEITWACHT_CE_CREDWATCH_EXCLUDE` (exclude); each is a comma-separated list
of path suffixes and an unset variable keeps the default. A suffix listed
as report-only is not watched even if it also appears in the watched list
(and an excluded suffix is neither). When two different suffixes match
one path, the longest (most specific) one decides.
`off` mode and the `leitwacht.io/allow-cred-read` label still suppress
events entirely.

### `job_overrides`

Optional per-CI-job overrides for `credwatch` / `proc_mem`. Keys are CI
job names; each entry may set either or both detector modes and wins over
the scope default for that job. A detector omitted in an override inherits
the scope default.

## Rule

```yaml
- pattern: <string>          # required
  pattern_type: <enum>       # required: domain | wildcard | ip | cidr
  action: <enum>             # required: allow | block
  resolution: <enum>         # optional, fqdn-block only: nxdomain | sinkhole
  ports: [80, 443]           # required for allow + domain/wildcard; otherwise optional
  reason: "free-text"        # optional, surfaced in violation reports
```

> Per-rule `audit` is intentionally not supported — audit is a scope-
> level mode (`default_action: audit`), not a rule-level decision. A
> rule listing `action: audit` is rejected at parse time.

### `pattern_type` values

| Value      | Meaning                                                     |
| ---------- | ----------------------------------------------------------- |
| `domain`   | Exact FQDN match (e.g., `github.com`).                      |
| `wildcard` | FQDN with `*` labels (e.g., `*.amazonaws.com`).             |
| `ip`       | Single IPv4 address.                                        |
| `cidr`     | Single-host IPv4 CIDR (`/32` only, e.g., `192.0.2.1/32`; equivalent to `ip`). |

The egress allow/deny maps are exact-match IPv4 hashes, so the loader
**rejects** (the load fails, or on hot-reload the previous rule set stays
active) any `ip`/`cidr`/`deny_ips` entry that is IPv6 or a multi-host
prefix such as `/8` or `/24`. Previously these were accepted and then
skipped at attach time with only a log warning, i.e. they never
enforced. Likewise rejected: domain/wildcard patterns that carry a
scheme (`https://host`), a port (`host:443`), a path, an IP literal
(use `pattern_type: ip`), an empty label, a label over 63 or a name over
253 characters, non-ASCII (write internationalised names in `xn--`
punycode form), any character outside `a-z 0-9 - _ * .`, and ports
outside the datapath range. A single trailing dot (`example.com.`) is
stripped. In `*` patterns the `*` must be a whole label (no `api*`, no
`**`), a bare `*` is rejected, and block rules accept `*` only as the
first label (`*.example.com`); allow rules may use it in any label.

`domain` and `wildcard` are both stored as FQDN rules at runtime —
agentcore's matcher walks domain labels and applies wildcard semantics
automatically.

### `resolution` values

Only meaningful when `action: block` AND `pattern_type` is `domain` or
`wildcard`. Controls how the in-netns DNS proxy answers blocked
queries.

| Value      | Behaviour                                                |
| ---------- | -------------------------------------------------------- |
| `nxdomain` | Proxy returns NXDOMAIN. Default for FQDN denies.         |
| `sinkhole` | Proxy returns the configured sinkhole IP, the eBPF deny map then drops the connection. Useful for catching exfil tools that ignore DNS errors. |

### `ports`

List of TCP ports, each `1..65535` for domain/wildcard rules and
`0..65535` for ip/cidr rules (`0` = any port). `deny_ips[].port` accepts
`0..65535`. Out-of-range values are rejected; they would otherwise wrap
in the 16-bit map key (65979 becomes 443, 65536 becomes 0 = any port).
**Required** when `action: allow` and
`pattern_type` is `domain` or `wildcard`. Optional for
ip/cidr rules (empty means any port). Ignored for domain/wildcard
`block` rules, which block the whole name.

When an FQDN allow rule lists no ports, the DNS proxy falls back to a
built-in default of `443` and `80`, which is rarely what the operator
meant. CE and the EE counterpart therefore force operators to spell out
the ports they actually need, so the rule says what it enforces.

CIDR/ip rules still accept empty ports, which means "any port on this
address".

## Stability

Schema v1 is stable. Adding optional fields is backwards-compatible
and stays under v1; any breaking change advances `schema_version` to
2 with explicit migration notes.

## Example: minimal default-block

```yaml
schema_version: 1
scopes:
  - name: default
    default_action: block
    rule_sets:
      "":
        - pattern: registry.gitlab.com
          pattern_type: domain
          action: allow
        - pattern: "*.docker.io"
          pattern_type: wildcard
          action: allow
        - pattern: 169.254.169.254
          pattern_type: ip
          action: block
          reason: "block IMDSv1 on AWS"
```
