# Roadmap

Cairn's mission: let a lean team operate infrastructure like a big one by
absorbing the toil across DevOps, SRE, FinOps and DevSecOps — locally, openly,
and under an explicit trust model. The sequence below is deliberate: each
stage earns the trust the next one spends.

## v0.1 — the wedge (shipped)

Local-first Terraform auditor fusing cost + security in one pass, with fixes,
policy-as-code, SARIF/JSON output and an audit trail. Strictly read-only.

## v0.2 — fit the workflow (shipped)

- `cairn propose` — the first Trust Ladder rung above read-only:
  Cairn drafts the change set; a human reviews and applies (wired to
  PR comments via the documented `gh` pattern).
- Inline suppressions (`# cairn:ignore RULE reason=...`) with mandatory
  reasons, mirroring `.cairn.yaml` ignores.
- Three new AWS rules (plaintext listeners, deletion protection,
  orphaned volumes).

## v0.3 — breadth with the same spine (shipped)

- **Kubernetes manifest scanning** through the unified findings model.
- **Policy packs** via `extends:` (bundled + in-repo, traversal-safe).
- **Pre-merge cost simulation** (`cairn diff`) with budget gates.
- **HTML report** and the **open-core editions boundary** in code.

## v0.4 — the knowledge graph (shipped)

Digital-twin resource graph, blast-radius on findings, plugin SDK, and
read-only drift detection.

## v0.4.5 — multi-cloud & on-prem (shipped)

Azure, GCP, and VMware vSphere rule packs; the provider dimension and
`--provider` filter; multi-cloud price books; air-gapped operation.

## v0.5.1 — coverage transparency (shipped)

A scan never claims "clean" for resources it didn't check; `cairn
providers` shows coverage. The cloud-agnostic pivot made honest and
visible. See [docs/coverage.md](docs/coverage.md).

## v0.5 — guarded autonomy (shipped)

Trust Ladder rung 2 for a provably-safe fix whitelist, plus the Azure
module.

## v1.0 — general availability (designed)

Contract permanence: every public surface semver-frozen for 1.x, with
explicit graduation criteria.

## Non-goals

- A hosted SaaS scanner. Local-first is the trust model, not a limitation.
- A browser extension (cannot reach local infra).
- Replacing engineers. Cairn is a companion: it does the 2am grunt work;
  humans keep judgment and the final say.
