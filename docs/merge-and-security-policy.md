# Merge & Security Policy

How a change travels from a contributor's idea to production, and every
control that guarantees **only a maintainer makes the final merge and only
a maintainer ships a release.** This is the operational companion to
[GOVERNANCE.md](../GOVERNANCE.md).

The model in one line: **anyone contributes, a maintainer reviews, a
maintainer merges, a maintainer releases.** Contributors never hold write
access to this repository.

## 1. The contribution flow

```
Contributor forks  ->  pushes a branch to THEIR fork  ->  opens a PR
        |                                                     |
        v                                                     v
  CI runs on the PR (read-only token, no secrets)     Maintainer reviews
        |                                                     |
        +------------- all required checks green -------------+
                                   |
                        Maintainer approves (CODEOWNERS)
                                   |
                        Maintainer merges (squash)
                                   |
                 Maintainer tags v* -> gated release -> production
```

Contributors work entirely from a **fork**. They cannot push to this
repository at all — not to `main`, not to a feature branch here. That is
the primary, structural control; everything below reinforces it.

## 2. Branch protection (enforced on `main` and `release/*`)

Configured by the importable ruleset at
[`.github/rulesets/main-protection.json`](../.github/rulesets/main-protection.json)
(apply per the publishing guide). It requires:

- **Pull request before merge**, with **≥1 approving review from a
  maintainer**, and **required review from Code Owners** — because
  `CODEOWNERS` assigns every path to the maintainers team, every PR needs a
  maintainer's approval.
- **Stale approvals dismissed on new commits** — a re-push re-opens review.
- **Only maintainers may dismiss reviews** — a contributor cannot clear a
  maintainer's objection.
- **All required status checks green and branch up to date**: `lint`,
  `test` (the OS/Python matrix), `security` (pip-audit), `docs`, and
  `CodeQL`.
- **Conversation resolution required** — no unresolved review threads.
- **Linear history + squash-only merges** — one reviewed commit per change.
- **Force-pushes and deletions blocked**, **including for administrators**
  (maintainers hold themselves to the same gate).
- **Push access to the protected branch restricted to the maintainers
  team** — even a maintainer lands changes via reviewed PR, not a direct
  push.

## 3. Who can merge — and who cannot

| Action | Contributor | Triager | Maintainer |
|---|---|---|---|
| Open issue / PR (from fork) | ✅ | ✅ | ✅ |
| Comment / review (non-binding) | ✅ | ✅ | ✅ |
| Approve as Code Owner | ❌ | ❌ | ✅ |
| Merge a PR | ❌ | ❌ | ✅ |
| Push to `main` / `release/*` | ❌ | ❌ | ✅ (via PR only) |
| Create a `v*` release tag | ❌ | ❌ | ✅ |
| Publish to PyPI / registry | ❌ | ❌ | ✅ (gated env) |
| Change repo settings / secrets / workflows | ❌ | ❌ | ✅ |

Repository collaborator access is granted at **Read** (or **Triage** for
trusted triagers) for everyone except maintainers. **Write/Maintain/Admin
is held only by the people in `MAINTAINERS.md`.**

## 4. Release authority (pushing to production)

"Production" for Cairn is the published PyPI package, the container
image, and the Marketplace Action. Three independent controls keep it
maintainer-only:

1. **Protected tags.** Only maintainers can create `v*` tags. The release
   workflow triggers on those tags, so no one else can start a release.
2. **Gated deployment environment.** The `pypi` environment has a
   maintainer as a **required reviewer**; the publish job pauses for
   explicit maintainer approval even after a tag is pushed.
3. **Trusted publishing (OIDC), no long-lived tokens.** There is no PyPI
   API token in the repo to leak; publishing is bound to the maintainer-
   controlled workflow and environment.

A contributor whose change is merged still cannot cause a release. The
merge and the release are two separate maintainer actions.

## 5. Security considerations for accepting outside contributions

A mature project assumes pull requests can be hostile and designs CI so a
malicious PR cannot steal secrets or reach production:

- **Fork PRs run with a read-only `GITHUB_TOKEN` and no repository
  secrets.** A PR cannot exfiltrate credentials because none are exposed to
  it.
- **No `pull_request_target` that checks out and executes PR head code.**
  That pattern is the classic "pwn request" and is prohibited; CI uses
  `pull_request` (untrusted, sandboxed) for anything that runs contributor
  code.
- **First-time contributors' workflow runs require maintainer approval**
  (repository setting), so contributor code doesn't execute in CI until a
  maintainer has glanced at it.
- **Least-privilege workflow permissions.** Top-level `permissions:
  contents: read`; jobs escalate only what they need (e.g.
  `security-events: write` for CodeQL, `id-token: write` only in the
  gated publish job).
- **`persist-credentials: false` on checkouts**, so the git token isn't
  left on disk for later steps to abuse.
- **Supply chain.** Dependencies are minimal, floor-pinned, and scanned
  (`pip-audit`, CodeQL, Dependabot). Adding a runtime dependency is a
  consequential change (two-maintainer review).
- **Security-sensitive paths get owner review.** `CODEOWNERS` routes the
  parser, LLM adapter, audit, editions boundary, and all CI workflows to
  the maintainers team specifically, so changes there cannot merge on a
  generic approval.

## 6. What blocks a merge (the reviewer's checklist)

A maintainer merges only when **all** hold:

- [ ] All required checks are green (lint, types, tests+coverage,
      pip-audit, docs-freshness, CodeQL).
- [ ] The change has tests: rules ship ≥1 positive and ≥1 negative case;
      bug/security fixes ship the regression test that would have caught
      them.
- [ ] `examples/clean` still produces **zero** findings (no false
      positives introduced).
- [ ] No public contract changed without a version note and, if breaking,
      a second maintainer's agreement.
- [ ] `CHANGELOG.md` updated; generated docs regenerated if rules changed.
- [ ] No secrets, credentials, or unexplained network calls introduced;
      security-sensitive paths carry an owning maintainer's approval.
- [ ] Every review conversation resolved.

If any box is unchecked, the PR waits. The default is not to merge.

## 7. Handling a security report

Vulnerabilities are reported privately (GitHub Private Vulnerability
Reporting; see [SECURITY.md](../SECURITY.md)) and are visible only to
maintainers. Fixes are developed on a private fork, reviewed under the same
merge gate, and released by a maintainer with a coordinated disclosure and
a credited advisory. The reporting channel is never a public issue.
