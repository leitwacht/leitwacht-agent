# Contributing to leitwacht-agent

Thanks for your interest in contributing. leitwacht-agent is the
data-plane for an egress-control system for GitLab CI runners — bug
reports, patches, and design feedback are all welcome.

## Where to file things

The canonical home of this project is **GitLab.com**:

- Issues: <https://gitlab.com/leitwacht/leitwacht-agent/-/issues>
- Merge requests: <https://gitlab.com/leitwacht/leitwacht-agent/-/merge_requests>
- Pipelines: <https://gitlab.com/leitwacht/leitwacht-agent/-/pipelines>

If a GitHub mirror exists at `github.com/leitwacht/leitwacht-agent`,
treat it as **read-only**. Issues and pull requests opened on GitHub
are not monitored — please open them on GitLab instead.

For security issues, follow [SECURITY.md](SECURITY.md) instead of
filing a public issue.

## Before you open an issue

- Search existing issues — including closed ones — to avoid duplicates.
- For bug reports, include: leitwacht-agent version (image digest or
  git SHA), kernel version, container runtime (containerd / Docker)
  and version, the rule set you were running, and the observed vs.
  expected behaviour.
- For feature requests, describe the use case before the proposed
  solution. We'd rather hear "my CI jobs need to reach an internal
  proxy that uses mTLS" than "please add field X to the YAML schema."

## Development setup

leitwacht-agent is **Linux-only** at runtime — eBPF, nftables, and
the LSM credwatch/proc_mem hooks all assume a Linux kernel. macOS works for editing
but you cannot run the integration tests there.

```sh
# Build
GOOS=linux GOARCH=amd64 go build ./...

# Lint
go vet ./...
gofmt -l .

# Tests (Linux only — most code is build-tagged)
go test -race -count=1 -tags=linux ./...
```

The eBPF object files (`*_bpfel.o`, `*_bpfel.go`) are **committed** to
the repo because regenerating them requires `clang` and kernel headers.
If you change a `.bpf.c` source file, regenerate locally on Linux:

```sh
go generate ./agentcore/enforcer/
```

CI builds rely on the committed artefacts and does not regenerate them.

### One-time CI bootstrap

The `release` stage runs [go-semantic-release](https://github.com/go-semantic-release/semantic-release)
to publish tags + changelog from Conventional Commit messages. It needs
a project access token with `api` and `write_repository` scopes:

1. Project → Settings → Access Tokens → create a token named
   `semantic-release` with the `api` and `write_repository` scopes.
2. Settings → CI/CD → Variables → add `GITLAB_TOKEN`, **masked** and
   **protected**, value = the token from step 1.

Image mirroring to quay.io additionally needs `QUAY_USER` and
`QUAY_TOKEN` masked+protected variables; the `mirror` stage skips
silently if they are not set.

## Submitting changes

1. Open a merge request on GitLab against `main`.
2. Use [Conventional Commits](https://www.conventionalcommits.org/) for
   commit messages: `feat(enforcer): support IPv6 in nftables sets`.
   This drives the changelog generator.
3. Keep the merge request focused — one concern per MR. Refactors and
   feature changes in the same MR will be sent back for splitting.
4. CI must be green before review. The `lint` and `test` stages run on
   every push; the `build` stage runs on `main` and on tags.
5. New features need tests. Bug fixes need a regression test that
   would have failed before the fix.
6. Update documentation when you change public behaviour: the
   top-level `README.md`, the rule schema reference at
   [`ce/SCHEMA.md`](ce/SCHEMA.md), and the Helm chart README at
   `ce/helm/agent-ce/README.md` — depending on which surface the
   change touches.

## Coding style

- Standard `gofmt`. CI rejects unformatted code.
- Errors: wrap with `fmt.Errorf("%w", err)` to preserve unwrap chains.
  Don't introduce a new error library.
- Logging: `log/slog` with structured key-value pairs. No `printf`-style
  log messages.
- Concurrency: prefer channels and contexts over shared mutable state.
  Long-running goroutines must respect a parent context.
- No new direct dependencies without a clear justification in the MR
  description. Vendored stdlib is preferred over a third-party module
  when both are reasonable.

## Licensing

By submitting a contribution you agree that your work is licensed under
the [Mozilla Public License 2.0](LICENSE) and that you have the right
to make the contribution under that license.

We do **not** require a Contributor License Agreement (CLA). The MPL-2.0
file-level copyleft is the only obligation on contributions.

## Code of conduct

This project follows the
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Please read it before
participating.
