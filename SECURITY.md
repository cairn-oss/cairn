# Security Policy

Cairn is a security tool; we hold it to the standard we scan for.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open a
public issue.

You can expect an acknowledgment within 72 hours and a triage decision within
7 days. We credit reporters in the release notes unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Cairn's own security posture

**Data handling — the local-first contract**

- Scans execute entirely on your machine. Cairn makes **no network calls
  by default** — no telemetry, no update checks, no uploads.
- The only network path is the **opt-in** `--explain` feature, which sends
  *only* the finding itself (rule ID, severity, resource address, message,
  fix text) to the LLM provider **you** configure with **your** key — or to
  a fully local Ollama instance. File contents, variables, state and
  credentials are never transmitted. See `src/cairn/llm.py`; this
  contract is enforced in code and covered by tests.
- The audit log (`~/.cairn/audit.jsonl`) stays local and contains scan
  metadata only (counts, durations, exit codes) — no findings bodies, no
  file contents.

**Execution posture**

- Read-only: v0.1 never modifies your files, your cloud, or your Git state
  (Trust Ladder rung 0). Higher autonomy rungs will always be explicit,
  per-category opt-ins with full audit.
- No shell-outs, no `eval`, no dynamic code loading. Parsing untrusted
  Terraform is contained per file: a malicious or malformed file can at
  worst fail its own parse. Files over 10 MiB are skipped (reported), and
  directory symlinks are never followed, so a scanned repository cannot
  route the scan outside itself or into a cycle.

**Hardened against hostile repository configs**

A scanned repository may ship its own `.cairn.yaml`; Cairn treats
that file as untrusted input:

- `llm.base_url` must be `https://`, or `http://` strictly to localhost —
  a malicious config cannot redirect your API key to an attacker host.
- `audit.path` must be a plain `.jsonl` file (enforced at config load and
  again at the write site, where symlinks are refused) — a config cannot
  turn the audit log into an append primitive against shell rc files.
- The Docker image runs as a non-root user with a read-only mount pattern
  (`-v "$PWD:/scan:ro"` recommended).

**Supply chain**

- Two runtime dependencies (`python-hcl2`, `PyYAML`), pinned by floor and
  scanned in CI (`pip-audit`, CodeQL, Dependabot).
- Releases are built by CI from tags; wheels and sdists are published with
  provenance attestation.

## Verifying a release

Every release is built by CI from a signed tag and ships with two artifacts
that let you verify what you install:

- **Build provenance** (SLSA, via Sigstore). Verify a downloaded wheel:

  ```
  gh attestation verify cairn_iac-<version>-py3-none-any.whl \
    --repo cairn-oss/cairn
  ```

- **A CycloneDX SBOM** attached to the GitHub release, listing the exact
  runtime dependency closure of the published artifact.

`pip install` is served through PyPI Trusted Publishing (OIDC); no long-lived
tokens are stored anywhere.
