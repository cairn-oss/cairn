# Repository rulesets

Importable GitHub rulesets that mechanically enforce the
[merge & security policy](../../docs/merge-and-security-policy.md):
**only maintainers merge, and only maintainers release.**

| File | Enforces |
|---|---|
| `main-protection.json` | On `main` and `release/*`: PR + maintainer (Code Owner) approval, all checks green and up to date, stale-review dismissal, thread resolution, squash-only, linear history, no force-push or deletion. |
| `tag-protection.json` | `v*` release tags cannot be created, moved, or deleted except by maintainers — so no one else can start a release. |

## About `bypass_actors`

`actor_id: 5` is the built-in **Maintain** repository role, and
`actor_id: 1` (not used here) would be Admin. Only these roles — held
solely by the people in [MAINTAINERS.md](../../MAINTAINERS.md) — may act
under the bypass rules. Everyone else is fully constrained. On
`main-protection`, maintainers bypass in `pull_request` mode only: they
still go through a reviewed PR, they simply aren't blocked by the same
external-contributor push restriction.

## Apply

Requires an org/repo admin (a maintainer) and the GitHub CLI:

```bash
gh api -X POST repos/cairn-oss/cairn/rulesets \
  --input .github/rulesets/main-protection.json
gh api -X POST repos/cairn-oss/cairn/rulesets \
  --input .github/rulesets/tag-protection.json
```

Then, in repository settings, complete the two controls rulesets do not
cover (see the publishing guide):

- **Collaborators & teams:** grant everyone **Read**; grant **Write** only
  to `@cairn-oss/maintainers`. This is what actually denies contributors
  push access — rulesets constrain *how* the privileged act, collaborator
  roles decide *who is* privileged.
- **Environments → `pypi`:** add a maintainer as a **required reviewer** so
  publishing pauses for explicit sign-off.
- **Actions → General:** require approval for **all outside
  collaborators'** workflow runs.
