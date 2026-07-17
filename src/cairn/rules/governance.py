"""Built-in governance rules (GOV···) — tagging and cost attribution."""

from __future__ import annotations

from collections.abc import Iterator

from cairn.findings import Category, Severity
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource

#: Resource types where untagged resources break cost attribution.
_TAGGABLE = (
    "aws_instance",
    "aws_s3_bucket",
    "aws_db_instance",
    "aws_ebs_volume",
    "aws_security_group",
    "aws_eip",
    "aws_launch_template",
)


@rule(
    id="GOV001",
    title="Resource has no tags",
    category=Category.GOVERNANCE,
    severity=Severity.LOW,
    description=(
        "Untagged resources cannot be attributed to a team, environment or "
        "cost center — FinOps and ownership both go blind."
    ),
    resource_types=_TAGGABLE,
    references=("https://docs.aws.amazon.com/whitepapers/latest/tagging-best-practices/tagging-best-practices.html",),
)
def missing_tags(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if not res.tags():
        yield Detection(
            message="Resource has no tags — cost allocation and ownership are untrackable.",
            fix="Add at least Name, Environment and Owner tags.",
            fix_code=(
                'tags = {\n  Name        = "<name>"\n'
                '  Environment = "<environment>"\n  Owner = "<team>"\n}'
            ),
        )


@rule(
    id="GOV002",
    title="Required tag missing (org policy)",
    category=Category.GOVERNANCE,
    severity=Severity.MEDIUM,
    description=(
        "The organization's policy (required_tags in .cairn.yaml) "
        "mandates tags this resource does not carry. Inactive unless "
        "required_tags is configured."
    ),
    resource_types=_TAGGABLE,
)
def required_tags(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if not ctx.required_tags:
        return
    tags = res.tags()
    missing = [t for t in ctx.required_tags if t not in tags]
    if missing:
        yield Detection(
            message=f"Missing required tag(s): {', '.join(missing)} (org policy).",
            fix="Add the mandated tags so the resource passes organization policy.",
            fix_code="tags = {\n" + "\n".join(f'  {t} = "<value>"' for t in missing) + "\n}",
        )
