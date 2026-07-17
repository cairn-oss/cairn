# Changelog

All notable changes to Cairn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] — 2026-07-17

Packaging and documentation polish for the first public release on PyPI.

### Changed
- Distributed as `cairn-iac` on PyPI; CLI command `cairn`; config `.cairn.yaml`.
- No rule IDs, report schemas, exit codes, or CLI flags changed.

## [0.5.1] — 2026-07-08

Coverage transparency — the honesty fix that turns Cairn's cloud-agnostic
architecture into a trustworthy user experience.

### Added
- **`cairn providers`** lists covered providers (AWS, Azure, GCP,
  Kubernetes, on-prem vSphere) and the rule count for each.
- **Coverage reporting.** Every scan distinguishes *checked* resources from
  those *parsed but not checked* (a provider with no rule pack). The JSON
  report gains an additive `coverage` block and `summary.covered_resources`.
- **Broader provider inference.** Oracle Cloud, DigitalOcean, Alibaba, IBM,
  OpenStack and others are named (not "other") so coverage gaps are precise.

### Changed
- **A scan is only reported "Clean" when every resource belongs to a
  covered provider.** Otherwise Cairn says "checked N of M" and lists the
  unscanned types — fixing a trap where an Azure/GCP/Oracle scan on an
  AWS-only build previously reported a misleading "clean".


## [0.5.0] — 2026-07-08

Guarded autonomy — the first Trust Ladder rung that writes to your files.

### Added
- **`cairn fix`** (Trust Ladder rung 2). Applies a hard-coded whitelist
  of non-destructive, attribute-only fixes (gp2→gp3, enable RDS/EBS
  encryption, deletion protection). Dry-run by default; `--apply` writes.
- **Per-category autonomy grants** (`autonomy.allow` in policy; `[]` is a
  kill switch). Nothing not both whitelisted and granted is ever applied.
- **Clean-worktree guard**: applying refuses unless the target is a clean
  git checkout, so every change is a reviewable, revertible diff.
- **Audited application**: each applied change records before/after content
  hashes under a `fix-apply` audit action.

### Security
- The apply path edits only files inside the scanned repository, cannot be
  widened by a scanned repo's config (the whitelist is code), and never
  guesses — a fix whose exact text isn't found is skipped and reported.


## [0.4.5] — 2026-07-08

Multi-cloud and on-prem, through the same pipeline.

### Added
- **Provider dimension.** Every finding is tagged with its provider
  (aws/azure/gcp/vsphere/kubernetes), inferred from the resource type and
  emitted in JSON. `cairn scan --provider aws,azure` filters by it.
- **Azure rule pack** (AZ001–AZ006): NSG exposure, public storage/SQL,
  unencrypted disks, oversized VMs (with cost estimates), tagging.
- **GCP rule pack** (GCP001–GCP006): open firewalls, public buckets and
  Cloud SQL, Shielded VM, oversized machines (with cost estimates), labels.
- **VMware vSphere pack** (VS001–VS003): on-prem reliability, thin
  provisioning, ownership — the private-cloud / on-prem target.
- **Multi-cloud price books** (Azure VM, GCP machine types), offline.
- **Air-gapped operations guide** (docs/air-gapped.md).


## [0.4.0] — 2026-07-08

The knowledge graph, an ecosystem seam, and drift detection — all local,
all read-only.

### Added
- **Resource graph + blast radius.** A local dependency graph (references,
  `depends_on`, Kubernetes selectors) attaches each finding's transitive
  dependents as `blast_radius`. Shown in console/HTML, emitted in JSON.
- **Plugin SDK v1.** Rule packages advertising the `cairn.rules` entry
  point load automatically with provenance shown in `cairn rules`;
  `--no-plugins` forces a builtin-only run; broken plugins are contained.
- **Drift detection.** `cairn drift PATH STATE` compares declared IaC
  against a `terraform show -json` snapshot you produce — no cloud
  credentials read.

### Changed
- JSON report `schema_version` is now `2` (additive `blast_radius` field;
  existing consumers unaffected).


## [0.3.0] — 2026-07-07

Breadth with the same spine: a second IaC target, shareable policy, and
cost review at the pull request — all through the unchanged v0.1
findings model.

### Added
- **Kubernetes manifest scanning**: Deployments, StatefulSets,
  DaemonSets, Jobs, CronJobs and Pods flow through the same pipeline as
  Terraform (`k8s_*` resource types). Six rules: privileged containers
  (K8S001), root containers (K8S002), hostPath mounts (K8S003), unpinned
  images (K8S004), missing resource limits (K8S005), missing probes
  (K8S006).
- **Policy packs**: `extends:` in `.cairn.yaml` layers bundled packs
  (`strict-security`, `cost-guard`) or relative in-repo packs under your
  overrides. Traversal-safe by construction: relative paths only,
  no escapes, packs cannot extend packs.
- **`cairn diff`**: estimated monthly cost movement between two
  configurations, with an optional `budget.max_monthly_increase` gate
  (exit 1 on breach).
- **HTML report** (`--format html`): one self-contained file, no
  JavaScript, no external assets.
- **`cairn license` + editions seam**: the free/paid boundary is now
  code (`cairn.editions`). All
  shipped capabilities are enumerated free-forever and test-enforced;
  commercial capabilities attach via the `cairn.commercial` entry
  point and can never degrade the core.

### Security
- Kubernetes parsing treats repositories as hostile input: 2 MiB file
  ceiling, YAML anchor-bomb guard, symlinked directories never followed,
  per-file error containment.
- `extends` refuses absolute paths and directory escapes.

### Fixed
- Scanning a single non-`.tf` file no longer produces a spurious HCL
  parse error alongside the correct parser's output.

## [0.2.0] — 2026-07-07

Fit the workflow: the first Trust Ladder rung above read-only, and
documented exceptions instead of silent ones.

### Added
- **`cairn propose`** (Trust Ladder rung 1): drafts a review-ready
  remediation proposal — per-file patches, rationale, sequencing — for a
  pull-request description or `gh pr comment --body-file`. Changes
  nothing; audited as its own action type.
- **Inline suppressions**: `# cairn:ignore RULE reason=...` inside a
  resource block suppresses that rule for that resource. Reasons are
  mandatory — a marker without one does not suppress and surfaces as a
  warning. Suppressed findings and reasons appear in the JSON report.
- **Three rules**: SEC010 plaintext HTTP load-balancer listener (redirect
  pattern recognized), REL003 database deletion protection disabled,
  COST006 EBS volume attached to nothing (with $/month estimate).
- `examples/suppressed/` demonstrating documented exceptions end-to-end.

### Changed
- Console output now reports suppression counts and scan warnings.
- JSON report: additive `suppressed` and `warnings` fields
  (schema_version stays 1; existing consumers are unaffected).

## [0.1.0] — 2026-07-07

First public release: the local-first Terraform cost + security wedge.

### Added
- **Scan engine**: recursive Terraform (HCL2) discovery and parsing with
  per-file error isolation and line-number recovery.
- **18 built-in rules** across four disciplines:
  security (SEC001–SEC009), cost (COST001–COST005), reliability
  (REL001–REL002) and governance (GOV001–GOV002).
- **Cost estimates**: offline price book puts an indicative $/month figure
  next to right-sizing, gp2→gp3, idle-EIP and old-generation findings.
- **Trade-off reconciliation**: cost × security/reliability collisions on
  the same resource are surfaced as a single sequenced decision.
- **Policy-as-code** (`.cairn.yaml`): min severity, CI fail threshold,
  required tags, disabled rules, severity overrides, glob-based ignores
  with reasons.
- **Reporters**: console (ANSI), JSON (versioned schema), SARIF 2.1.0
  (GitHub Code Scanning), Markdown.
- **Opt-in LLM explanations**: bring-your-own-key OpenAI/Anthropic or fully
  local Ollama; graceful degradation; nothing sent without explicit opt-in.
- **Audit trail** (Trust Ladder rung 0): append-only local JSONL log of
  every scan.
- **CLI** with stable CI exit codes (0/1/2), `rules` catalogue command,
  `--fail-on NEVER`, `--min-severity`, `--quiet`, `NO_COLOR` support.
- **Distribution**: PyPI packaging, Dockerfile (non-root, slim), composite
  GitHub Action.

### Security
- `llm.base_url` restricted to `https://` or loopback `http://`, so a
  scanned repository's config cannot exfiltrate the user's API key.
- `audit.path` restricted to `.jsonl` files (validated at load and at the
  write site; symlinks refused).
- Scan discovery never follows directory symlinks; files over 10 MiB are
  skipped and reported.

[Unreleased]: https://github.com/cairn-oss/cairn/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/cairn-oss/cairn/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/cairn-oss/cairn/compare/v0.4.5...v0.5.0
[0.4.5]: https://github.com/cairn-oss/cairn/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/cairn-oss/cairn/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cairn-oss/cairn/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cairn-oss/cairn/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cairn-oss/cairn/releases/tag/v0.1.0
