# Security policy

## Reporting a vulnerability

The leitwacht team takes security issues seriously. Please **do not** open
public issues or merge requests for suspected vulnerabilities. If a
GitHub mirror exists, it is read-only and not monitored.

To report a vulnerability, choose one of:

1. **Private GitLab security issue** (preferred):
   <https://gitlab.com/leitwacht/leitwacht-agent/-/issues/new?issuable_template=security>

   Mark the issue **Confidential** before submitting. Confidential issues
   are visible only to project members.

2. **Email**: <security@leitwacht.eu>

   Mark the subject line **`[security]`** so the thread is routed
   directly to maintainers. If you need encrypted-in-transit reporting,
   use the GitLab confidential issue route above — GitLab.com encrypts
   issue payloads at rest and the bot account that monitors them is
   restricted to maintainers.

GitHub Security Advisories on the mirror repository are **not** monitored.
Reports filed there will be closed with a pointer to this document.

## What to include

- A description of the vulnerability and the affected component(s)
  (`agentcore/enforcer`, `leitwacht-initc`, etc.).
- The version(s) of leitwacht-agent affected — the image digest or git
  commit SHA is most useful.
- A reproduction: minimal steps, configuration, and (where applicable)
  a proof-of-concept rule set or container image.
- Your assessment of impact (what an attacker can do, under what
  preconditions).
- Whether the issue is already public anywhere, and whether you intend
  to publish.

We aim to acknowledge receipt within **3 business days** and provide
an initial triage assessment within **7 business days**. For confirmed
high-severity issues we target a fix or mitigation within **30 days**;
the timeline for lower-severity issues is negotiated with the reporter.

## Scope

In scope:

- The `agentcore/` library, the `ce/` daemon, and the `leitwacht-initc`,
  `agent-ce` binaries built from this repository.
- The published container images at
  `registry.gitlab.com/leitwacht/leitwacht-agent/{leitwacht-initc,agent-ce}`
  (and their `quay.io/leitwacht/*` mirrors).
- The Helm chart at `ce/helm/agent-ce/`.

Out of scope:

- The leitwacht Enterprise Edition backend (reported separately to the
  EE security contact).
- Vulnerabilities in upstream dependencies that are already publicly
  tracked under their own CVE — please report those upstream and let us
  know which version pin you'd like us to advance.
- Issues that require a privileged attacker who already has root on
  the runner host. leitwacht's threat model assumes the runner host
  itself is trusted; an attacker with host root can disable
  enforcement by design.

## Supported versions

leitwacht-agent uses semantic versioning. Only the **most recent minor
release on the current major** receives security patches. Older minors
receive fixes only for critical vulnerabilities (CVSS ≥ 9.0) and only
until the next major release.

| Version | Supported            |
| ------- | -------------------- |
| 0.x     | Latest minor only    |

A 1.0 release will introduce a longer-term support policy; the current
0.x line is pre-stable.

## Disclosure

We follow coordinated disclosure. Once a fix is available we will:

1. Publish a release with the patch.
2. Document the vulnerability in the GitLab Release notes and (for
   confirmed CVEs) request a CVE ID via MITRE.
3. Credit the reporter unless they request otherwise.

We do not currently operate a bug-bounty programme.

## Verifying release artefacts

All container images are signed with cosign keyless signing via the
GitLab CI OIDC issuer. Verify any of `agent-ce`, `leitwacht-initc`
before deploying — replace `<image>` below:

```sh
cosign verify registry.gitlab.com/leitwacht/leitwacht-agent/<image>:<tag> \
  --certificate-identity-regexp 'https://gitlab\.com/leitwacht/leitwacht-agent//\.gitlab-ci\.yml@refs/.*' \
  --certificate-oidc-issuer https://gitlab.com
```

SBOMs (SPDX-JSON) are attached as cosign attestations:

```sh
cosign download attestation registry.gitlab.com/leitwacht/leitwacht-agent/<image>:<tag> \
  --predicate-type spdxjson
```
