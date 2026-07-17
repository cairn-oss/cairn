# Organization rulesets — `cairn-oss`

Organization-level rulesets that apply across **every repository** in the
`cairn-oss` org (`cairn`, `cairn-commercial`, and any future
repo), so the security posture is enforced centrally rather than
re-created per repo. They are the org-wide counterpart to the repo-level
rulesets in [`../`](../) and encode the same rule: **only maintainers
merge, and only maintainers release** — plus supply-chain protections
appropriate for a security tool.

Keep these JSON files in version control as governance-as-code: they are
the reviewable source of truth for how the org is protected, and can be
re-applied or diffed against the live configuration at any time.

| File | Target | What it enforces |
|---|---|---|
| `branch-protection.json` | `main`, `release/*` on all repos | PR + Code-Owner approval, all required checks green and up to date, **signed commits**, linear history, squash-only, stale-review dismissal, thread resolution; no force-push or deletion. |
| `tag-protection.json` | `v*` tags on all repos | Only maintainers may create, move, or delete release tags — so no one else can start a release. Tags must be signed. |
| `push-protection.json` | every push to all repos | Blocks pushing private-key file types and paths (`*.key`, `*.pem`, `secrets/**`, `.env`, SSH keys), Terraform state (`*.tfstate`, `terraform.tfvars`), and oversized files — defense in depth so a signing key or secret can never be committed even if `.gitignore` is bypassed. |

## Why these specifics

- **Signed commits and tags** (`required_signatures`) give provenance to
  every change and release — essential for a security tool whose users
  trust the supply chain. Configure commit signing before enabling, or
  contributors' unsigned commits will be blocked.
- **Push file/path restrictions** directly protect the assets this project
  treats as secret: the Ed25519 **signing key** used to issue commercial
  licenses (`signing.key`, `*.key`), billing secrets (`.env`), and cloud
  state (`*.tfstate`). The repo `.gitignore` already excludes these; the
  ruleset enforces it at the git layer, org-wide, with no bypass except the
  org owner.
- **Maintainer-only merge and release** is enforced by restricting the
  bypass actors: only the **Organization Admin** and the **Maintain**
  repository role (held solely by you) can act under these rules; on
  branches they still go through a reviewed PR (`bypass_mode:
  pull_request`).

## Apply

Requires org-owner access and the GitHub CLI. Create the org and the
`maintainers` team first, then:

```bash
for rs in branch-protection tag-protection push-protection; do
  gh api -X POST /orgs/cairn-oss/rulesets \
    --input .github/rulesets/org/$rs.json
done
```

List / update later:

```bash
gh api /orgs/cairn-oss/rulesets
gh api -X PUT /orgs/cairn-oss/rulesets/<id> --input <file>.json
```

## Notes on `bypass_actors`

- `OrganizationAdmin` (`actor_id: 1`) — the org owner (you). Primary bypass.
- `RepositoryRole` `actor_id: 5` — the built-in **Maintain** role. Grant it
  only to the `maintainers` team so exactly your maintainers are covered.
- To scope bypass to the **team** specifically, add an entry with
  `"actor_type": "Team"` and the team's numeric id once the team exists:
  `gh api /orgs/cairn-oss/teams/maintainers` returns it.

## Relationship to repo rulesets

The repo-level rulesets in [`../main-protection.json`](../main-protection.json)
and [`../tag-protection.json`](../tag-protection.json) remain valid for a
single-repo setup or as a stricter per-repo overlay. When both an org and a
repo ruleset apply, GitHub evaluates them together and the **most
restrictive** wins — so keeping both is safe. If you standardize on org
rulesets, the repo-level ones become redundant and can be removed.
