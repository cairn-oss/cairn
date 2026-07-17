# Contributing to Cairn

Thanks for considering a contribution — rules are small, the codebase is
typed and tested, and a first PR can genuinely land in an afternoon.

## How changes get in

Everyone is welcome to contribute; **a maintainer makes the final merge
after reviewing your pull request.** You work from a fork (you won't have
push access to this repository), open a PR, CI runs, a maintainer reviews
against the checklist below, and a maintainer merges.

**Merge policy — stated plainly, and enforced by GitHub, not by trust:**

- **Only maintainers can merge to `main`.** The `main` branch accepts no
  direct pushes; every change goes through a reviewed pull request, and only
  members of the [`@cairn-oss/maintainers`](MAINTAINERS.md) team have merge
  rights. This is enforced by a branch-protection ruleset, not by convention.
- **Contributors never need write access to this repository.** You fork, push
  to your own fork, and open a PR — that is the entire contributor path.
- **Releases to production** (PyPI, the container image, the GitHub Action)
  are cut only by maintainers, from signed tags.

The full model is in [GOVERNANCE.md](GOVERNANCE.md) and
[docs/merge-and-security-policy.md](docs/merge-and-security-policy.md).

```bash
# 1. Fork on GitHub, then:
git clone https://github.com/<you>/cairn && cd cairn
git remote add upstream https://github.com/cairn-oss/cairn
git checkout -b my-change
# 2. make changes, run the gate (below), push to YOUR fork
git push origin my-change
# 3. open a pull request against cairn-oss/cairn:main
```

## Development setup

```bash
git clone https://github.com/cairn-oss/cairn && cd cairn
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Everything the CI runs, you can run locally:

```bash
make check        # ruff + mypy + pytest, the full gate
make test         # tests only
make lint         # ruff only
make typecheck    # mypy (strict) only
```

## Writing a rule (the most valuable contribution)

A rule is one decorated function in `src/cairn/rules/`:

```python
@rule(
    id="COST007",                       # next free id in the family
    title="S3 bucket without a lifecycle policy",
    category=Category.COST,
    severity=Severity.LOW,
    description="Why this matters, in two sentences.",
    resource_types=("aws_s3_bucket",),
    references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",),
)
def s3_no_lifecycle(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if not res.body.get("lifecycle_rule"):
        yield Detection(
            message="Bucket has no lifecycle policy; old objects accrue cost forever.",
            fix="Add a lifecycle rule that transitions or expires stale objects.",
        )
```

Ground rules for rules:

1. **Fix, not just flag.** Every detection needs actionable `fix` text;
   include `fix_code` whenever a safe snippet exists.
2. **No false positives on the clean fixture.** `examples/clean/main.tf`
   must stay at zero findings — extend it if your rule needs a negative case.
3. **Cross-resource awareness.** If a companion resource can satisfy the
   requirement (e.g. `aws_s3_bucket_versioning`), check `ctx` — see
   `rules/_helpers.py`.
4. **Tests are required.** At least one positive and one negative case in
   `tests/test_rules_*.py`. Cost rules should assert the `monthly_cost` math.
5. **Stable IDs.** Rule IDs are a public contract (people ignore/override by
   ID). Never reuse or renumber.

Propose new rules first via the
[rule proposal issue template](.github/ISSUE_TEMPLATE/rule_proposal.yml) if
you want feedback before writing code.

## Pull request checklist

- [ ] `make check` passes (ruff, mypy --strict, pytest)
- [ ] New behavior has tests; rule changes update `examples/` if relevant
- [ ] `CHANGELOG.md` gets a line under **Unreleased**
- [ ] Docs updated (`docs/rules.md` regenerates via `make docs-rules`)
- [ ] Commits are focused; PR description explains *why*

We squash-merge; the PR title becomes the commit message (imperative mood,
e.g. "Add RDS deletion-protection rule").

## Code style

- Python ≥ 3.10, fully typed, `mypy --strict` clean.
- `ruff` enforces formatting-adjacent lint (line length 100, isort, etc.).
- Prefer plain functions and frozen dataclasses over class hierarchies.
- Docstrings explain *why*; the code should already say *what*.

## Architecture orientation

Read [docs/architecture.md](docs/architecture.md) (10 minutes) — it covers
the pipeline (parse → detect → policy → reconcile → report), the unified
findings model, and the Trust Ladder that governs everything action-shaped.

## Reporting security issues

Please do **not** open a public issue — see [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
