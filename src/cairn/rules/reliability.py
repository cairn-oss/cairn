"""Built-in reliability rules (REL···)."""

from __future__ import annotations

from collections.abc import Iterator

from cairn.findings import Category, Severity
from cairn.rules._helpers import blocks, has_companion
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource


@rule(
    id="REL001",
    title="Database has no automated backups",
    category=Category.RELIABILITY,
    severity=Severity.MEDIUM,
    description=(
        "backup_retention_period is 0 or unset, so point-in-time recovery "
        "is impossible: an accidental delete or corruption is permanent."
    ),
    resource_types=("aws_db_instance",),
    references=(
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
    ),
)
def rds_no_backups(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    retention = res.body.get("backup_retention_period", 0)
    try:
        retention = int(retention)
    except (TypeError, ValueError):
        return
    if retention <= 0:
        yield Detection(
            message="RDS automated backups are disabled (backup_retention_period is 0).",
            fix="Set backup_retention_period to at least 7 days (35 max) to enable PITR.",
            fix_code="backup_retention_period = 7",
        )


@rule(
    id="REL002",
    title="S3 bucket versioning disabled",
    category=Category.RELIABILITY,
    severity=Severity.LOW,
    description=(
        "Without versioning, overwritten or deleted objects are gone; with "
        "it, mistakes and ransomware-style overwrites are recoverable."
    ),
    resource_types=("aws_s3_bucket",),
    references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",),
)
def s3_no_versioning(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    inline = blocks(res.body, "versioning")
    if inline and inline[0].get("enabled") is True:
        return
    if has_companion(ctx, "aws_s3_bucket_versioning", "bucket", res):
        return
    yield Detection(
        message="S3 bucket has no versioning; deletes and overwrites are unrecoverable.",
        fix="Enable versioning via an aws_s3_bucket_versioning resource.",
        fix_code=(
            f'resource "aws_s3_bucket_versioning" "{res.name}" {{\n'
            f"  bucket = aws_s3_bucket.{res.name}.id\n"
            "  versioning_configuration {\n"
            '    status = "Enabled"\n'
            "  }\n"
            "}"
        ),
    )


@rule(
    id="REL003",
    title="Database can be deleted without protection",
    category=Category.RELIABILITY,
    severity=Severity.MEDIUM,
    description=(
        "deletion_protection is not enabled, so one wrong terraform destroy "
        "or console click removes the database and its endpoint."
    ),
    resource_types=("aws_db_instance", "aws_rds_cluster"),
    references=(
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
    ),
)
def rds_no_deletion_protection(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("deletion_protection") is not True:
        yield Detection(
            message="Deletion protection is disabled on this database.",
            fix="Set deletion_protection = true for anything you would miss.",
            fix_code="deletion_protection = true",
        )
