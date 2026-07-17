# Configuration reference

Cairn is configured by a `.cairn.yaml` file discovered next to the
scan target (or passed with `--config`). CLI flags override file settings.
Everything has a sensible default; an empty or absent file is valid.

## Full example

```yaml
# Findings below this severity are dropped from the report entirely.
# One of: CRITICAL | HIGH | MEDIUM | LOW | INFO      (default: INFO)
min_severity: LOW

# CI gate: exit 1 when findings at/above this severity remain.
# (default: HIGH)
fail_on: HIGH

# Tags every taggable resource must carry (activates rule GOV002).
required_tags: [Owner, CostCenter]

# Rules to disable entirely, by ID.
disabled_rules: [GOV001]

# Raise or lower a rule's severity for your org.
severity_overrides:
  COST002: MEDIUM

# Targeted, documented exceptions. `rule` and `resource` accept globs.
ignores:
  - rule: SEC001
    resource: aws_security_group.legacy_*
    reason: grandfathered until the Q3 migration

# Opt-in LLM explanations (used only with --explain).
llm:
  provider: none        # none | openai | anthropic | ollama
  model: ""             # provider default if empty
  base_url: ""          # override for OpenAI-compatible servers

# Local, append-only scan log (Trust Ladder rung 0).
audit:
  enabled: true
  path: ""              # default: ~/.cairn/audit.jsonl (must end in .jsonl)
```

Unknown keys are a hard error (exit 2): a typo in a security policy should
never silently pass.

## Policy packs (`extends`)

Share a baseline across repositories and layer local overrides on top:

```yaml
extends: [strict-security, team-baseline.yaml]
fail_on: HIGH        # your value wins over anything a pack sets
```

Bare names load packs bundled with Cairn (`strict-security`,
`cost-guard`). Anything else must be a **relative** `.yaml` path inside
the config's directory — absolute paths and `..` escapes are refused, and
packs cannot extend other packs, so the merge order is always reviewable:
defaults ← packs (in listed order) ← your file. Lists union; scalars and
per-rule overrides take the later value.

## Cost simulation (`cairn diff`)

```bash
cairn diff ./infra-main ./infra-branch
```

Prints the estimated monthly cost movement (added/removed/resized
resources, totals) from the offline price book. With a budget in policy:

```yaml
budget:
  max_monthly_increase: 500   # USD/month
```

`cairn diff` exits 1 when the change breaches the budget — cost review
at the pull request, not on next month's bill.

## HTML report

`cairn scan ./infra --format html --output report.html` writes a
single self-contained file (inline styles, no JavaScript, no external
assets) suitable for tickets, archives, or a quick local dashboard.

## Inline suppressions

Grant a documented exception directly in the code it concerns:

```hcl
resource "aws_security_group" "bastion" {
  ingress {
    # cairn:ignore SEC001 reason=reachable only through the corporate VPN
    from_port   = 22
    ...
  }
}
```

The marker applies to the resource block it sits in, for exactly one rule.
The `reason=` is mandatory: a marker without it does **not** suppress and
is reported as a warning — an exception nobody can explain is a bug, not
a policy. Suppressed findings (with reasons and marker lines) remain
visible in the JSON report and the audit trail. For broader, reviewable
exceptions prefer `ignores:` in `.cairn.yaml`.

Inline markers are a Terraform feature: Kubernetes manifests carry no line
positions, so a marker cannot attach to a K8s resource — it warns instead
of silently suppressing. Use `disabled_rules` or `ignores` (which match on
resource address) to make documented K8s exceptions.

## Drafting fixes: `cairn propose`

`cairn propose PATH` renders the scan as a review-ready remediation
proposal (per-file patches, rationale, sequencing of security-before-cost
fixes). It never modifies anything — Trust Ladder rung 1 is *propose*,
a human applies. Typical CI wiring:

```yaml
- run: |
    pip install cairn-iac
    cairn propose ./infra --output proposal.md
- run: gh pr comment "$PR_NUMBER" --body-file proposal.md
  env:
    GH_TOKEN: ${{ github.token }}
```

## CLI flags

```text
cairn scan PATH
  --format {console,html,json,markdown,sarif}   output format (default console)
  --output FILE                            write report to FILE
  --config FILE                            explicit policy file
  --min-severity SEV                       report floor (overrides file)
  --fail-on SEV|NEVER                      CI gate (overrides file)
  --explain                                LLM explanations (requires llm.provider)
  --no-color                               disable ANSI (NO_COLOR env also respected)
  --quiet                                  exit code only
  --no-plugins                             run built-in rules only (ignore plugins)
  --provider LIST                          restrict to providers (aws,azure,gcp,vsphere,kubernetes)

cairn fix PATH [--apply] [--config FILE]

cairn propose PATH [--output FILE] [--config FILE] [--explain]
cairn diff OLD NEW [--config FILE]
cairn drift PATH STATE          # STATE = terraform show -json output
cairn fix PATH [--apply] [--config FILE]   # rung 2: apply whitelisted fixes
cairn providers                 # covered providers + rule counts
cairn rules [--format {console,markdown}]
cairn license
cairn version
```

## Blast radius

Every finding now reports its **blast radius** — the resources that
transitively depend on the flagged one, derived offline from a local
resource graph (references, `depends_on`, and Kubernetes selectors). It
appears in the console output, the HTML report, and as `blast_radius` in
JSON (schema_version 2, additive). A misconfiguration fronting ten
downstream resources is triaged differently from an isolated one.

## Guarded autonomy: `cairn fix`

Trust Ladder rung 2 — the first time Cairn *writes* to your files, kept
deliberately narrow. `cairn fix PATH` shows what it *would* change
(dry run); `--apply` writes it. Only a hard-coded whitelist of
non-destructive, attribute-only fixes is eligible (gp2→gp3, enable
encryption, deletion protection), and each class must be granted in policy:

```yaml
autonomy:
  allow: [volume-types, encryption, deletion-protection]   # [] = kill switch
```

Applying refuses to run unless the target is a **clean git worktree**, so
every change is a reviewable, revertible diff; each is audited with
before/after content hashes. Nothing not both whitelisted *and* granted is
ever touched.

## Drift detection

`cairn drift PATH STATE` compares your declared Terraform against a
state snapshot **you** produce — Cairn reads no cloud credentials:

```bash
terraform show -json > state.json
cairn drift ./infra state.json      # exit 1 if drift is found
```

It classifies each resource as in-sync, missing (declared but not in
state), or unmanaged (in state but not declared).

## Providers (cloud-agnostic + on-prem)

Cairn scans AWS, Azure (`azurerm_*`), GCP (`google_*`), VMware vSphere
(`vsphere_*`), and Kubernetes manifests through one pipeline. The provider
is inferred from each resource type and attached to every finding
(`provider` in JSON). Filter to the platforms you care about:

```bash
cairn scan ./infra --provider aws,azure     # only AWS + Azure findings
cairn scan ./infra --provider vsphere       # on-prem only
```

Security, reliability, and governance rules exist for every provider;
cost estimates are cloud-only (on-prem hardware has no per-hour price). For
running with no internet access, see [air-gapped.md](air-gapped.md).

## Rule plugins

Third-party rule packages that advertise the `cairn.rules` entry point
are loaded automatically; `cairn rules` marks their provenance. For a
builtin-only run in CI, pass `--no-plugins` to `scan`. A broken plugin is
reported as a warning and skipped, never crashing a scan.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at/above `fail_on` (or `--fail-on NEVER`) |
| 1 | Findings at/above `fail_on` remain |
| 2 | Could not run: bad path, malformed config, usage error |

## Environment variables

| Variable | Effect |
|---|---|
| `OPENAI_API_KEY` | key for `llm.provider: openai` |
| `ANTHROPIC_API_KEY` | key for `llm.provider: anthropic` |
| `NO_COLOR` | disable ANSI colors |

## CI

### GitHub Actions (composite action)

```yaml
jobs:
  cairn:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only if uploading SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: cairn-oss/cairn@v0
        with:
          path: ./infra
          fail-on: HIGH
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cairn.sarif
```

### Any CI (plain CLI)

```bash
pip install cairn-iac
cairn scan ./infra --format sarif --output cairn.sarif --fail-on HIGH
```

The exit-code contract above is stable across releases.

## LLM providers

| Provider | Data path | Setup |
|---|---|---|
| `ollama` | fully local | `ollama serve` + `model: llama3.1` |
| `openai` | your key → OpenAI (or any OpenAI-compatible `base_url`) | `OPENAI_API_KEY` |
| `anthropic` | your key → Anthropic | `ANTHROPIC_API_KEY` |

Only the finding (rule, severity, resource address, message, fix) is ever
sent — never file contents. `base_url` must be `https://`, or `http://`
strictly to localhost — Cairn refuses anything else so a repository's
own config can never redirect your key. See [SECURITY.md](../SECURITY.md).
