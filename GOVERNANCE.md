# Governance

Cairn is **open to contribution, closed to unilateral change.** Anyone
may propose changes; only the core maintainers may merge them or ship a
release. This document defines who holds which rights and how decisions
are made. It is deliberately conservative: a security tool that anyone
could push to production would not be trustworthy.

## Roles

| Role | Who | Rights |
|---|---|---|
| **Maintainer** | The Cairn core team (see [MAINTAINERS.md](MAINTAINERS.md)) | Sole authority to approve and merge PRs, cut releases, publish packages, manage repository settings, add/remove collaborators, and administer secrets. |
| **Triager** *(optional, granted case-by-case)* | Trusted long-term contributors | Label, triage and close issues; review PRs (non-binding). **No merge, no write to protected branches, no release rights.** |
| **Contributor** | Anyone | Open issues and pull requests from a fork. No write access to this repository. |

Contribution volume, seniority, or employer grants no rights by itself.
Rights are held by named individuals in `MAINTAINERS.md`, never by a
company or an anonymous group.

## The one rule that defines the project

> **Only maintainers merge, and only maintainers release.**

This is enforced mechanically (branch protection + CODEOWNERS + protected
tags + a gated deployment environment — see
[docs/merge-and-security-policy.md](docs/merge-and-security-policy.md)),
not by trust. Every other rule in this document exists to support it.

## Decision-making

- **Ordinary changes** (rules, bug fixes, docs): a maintainer reviews,
  approves, and merges. One maintainer approval is the floor; anything
  touching a public contract or a security-sensitive path requires review
  from a maintainer who owns that path (CODEOWNERS enforces this).
- **Consequential changes** (breaking a public contract, changing the
  free/paid boundary, adding a runtime dependency, moving a Trust-Ladder
  rung): require agreement of **at least two maintainers**, recorded in
  the PR.
- **Disagreement** is resolved by the maintainers; if they are split, the
  lead maintainer decides. The bias is to *not* merge: an unmerged good
  idea can wait, a merged bad one ships to a security tool's users.

## Becoming a maintainer

Maintainership is offered by the existing maintainers, at their sole
discretion, to contributors with a sustained track record of high-quality,
security-conscious work and good community conduct. It is never automatic
and never requestable as a right. Adding a maintainer is itself a
consequential change (two-maintainer agreement) and is recorded in
`MAINTAINERS.md`.

Maintainers may step down at any time. Rights may be revoked by agreement
of the remaining maintainers for inactivity, breach of the Code of
Conduct, or a security-trust violation.

## What contributors can rely on

- Every PR gets a fair, timely review against published standards
  ([CONTRIBUTING.md](CONTRIBUTING.md)).
- Reviews judge the change, not the person.
- The free-forever capability set is contractual and will not shrink.
- Changes to *this* governance follow the consequential-change process and
  are announced.

## What contributors cannot do

- Push to `main` or any release branch (all pushes are via reviewed PR
  from a fork).
- Merge their own or anyone's PR.
- Create release tags (`v*`) or publish packages.
- Alter repository settings, secrets, CI workflows on protected branches,
  or this governance — except by proposing a PR a maintainer then merges.

## Amending this document

Changes to `GOVERNANCE.md` are consequential changes: two-maintainer
agreement, announced in the changelog. This keeps the rules of the project
as stable and reviewable as its code.
