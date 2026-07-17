"""Built-in DevSecOps rules (SEC···).

Every rule follows fix-not-just-flag: the detection carries concrete
remediation guidance and, where safe to generate, a ready-to-apply HCL
snippet.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from cairn.findings import Category, Severity
from cairn.rules._helpers import blocks, has_companion, is_interpolation, port_range_includes
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_ADMIN_PORTS = (22, 3389)


@rule(
    id="SEC001",
    title="Security group ingress open to the internet",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "An ingress rule allows traffic from 0.0.0.0/0 or ::/0. Exposing "
        "services to the whole internet is the most common cloud breach "
        "vector; SSH/RDP exposure is rated CRITICAL."
    ),
    resource_types=(
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    ),
    references=(
        "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
        "https://www.cisecurity.org/benchmark/amazon_web_services",
    ),
)
def open_ingress(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    entries: list[dict[str, Any]] = []
    if res.type == "aws_security_group":
        entries = blocks(res.body, "ingress")
    elif res.body.get("type", "ingress") == "ingress":
        entries = [res.body]

    for entry in entries:
        cidrs = entry.get("cidr_blocks") or []
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        cidrs = list(cidrs) + list(entry.get("ipv6_cidr_blocks") or [])
        if entry.get("cidr_ipv4") in _OPEN_CIDRS or entry.get("cidr_ipv6") in _OPEN_CIDRS:
            cidrs.append("0.0.0.0/0")
        if not any(c in _OPEN_CIDRS for c in cidrs):
            continue

        admin_exposed = str(entry.get("protocol", "")) == "-1" or any(
            port_range_includes(entry, p) for p in _ADMIN_PORTS
        )
        port = entry.get("from_port", "all")
        yield Detection(
            message=(
                f"Ingress on port {port} is open to the entire internet "
                f"(0.0.0.0/0){' and covers SSH/RDP' if admin_exposed else ''}."
            ),
            severity=Severity.CRITICAL if admin_exposed else None,
            fix=(
                "Restrict cidr_blocks to known ranges (office/VPN CIDRs), or "
                "front the service with a load balancer or SSM Session "
                "Manager instead of exposing it directly."
            ),
            fix_code='cidr_blocks = ["10.0.0.0/8"]  # replace with your trusted CIDR',
        )


@rule(
    id="SEC002",
    title="S3 bucket without server-side encryption",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "No server-side encryption is configured inline or via an "
        "aws_s3_bucket_server_side_encryption_configuration companion "
        "resource, so objects are stored unencrypted at rest."
    ),
    resource_types=("aws_s3_bucket",),
    references=(
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
    ),
)
def s3_no_encryption(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    inline = any(k.startswith("server_side_encryption") for k in res.body)
    companion = has_companion(
        ctx, "aws_s3_bucket_server_side_encryption_configuration", "bucket", res
    )
    if not inline and not companion:
        yield Detection(
            message="S3 bucket has no server-side encryption configured.",
            fix=(
                "Add an aws_s3_bucket_server_side_encryption_configuration "
                "resource (AES256, or aws:kms for key control and audit)."
            ),
            fix_code=(
                f'resource "aws_s3_bucket_server_side_encryption_configuration" "{res.name}" {{\n'
                f"  bucket = aws_s3_bucket.{res.name}.id\n"
                "  rule {\n"
                "    apply_server_side_encryption_by_default {\n"
                '      sse_algorithm = "AES256"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        )


@rule(
    id="SEC003",
    title="S3 bucket with a public ACL",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description="The bucket ACL grants public read (or read/write) access.",
    resource_types=("aws_s3_bucket", "aws_s3_bucket_acl"),
    references=(
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    ),
)
def s3_public_acl(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    acl = res.body.get("acl")
    if acl in ("public-read", "public-read-write"):
        yield Detection(
            message=f"S3 bucket ACL is '{acl}' — contents are exposed publicly.",
            severity=Severity.CRITICAL if acl == "public-read-write" else None,
            fix=(
                "Set the ACL to 'private' and add an "
                "aws_s3_bucket_public_access_block resource. Serve public "
                "assets through CloudFront with Origin Access Control instead."
            ),
            fix_code='acl = "private"',
        )


@rule(
    id="SEC004",
    title="Database instance is publicly accessible",
    category=Category.SECURITY,
    severity=Severity.CRITICAL,
    description="publicly_accessible = true puts the database on the public internet.",
    resource_types=("aws_db_instance", "aws_rds_cluster_instance"),
    references=(
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
    ),
)
def rds_public(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("publicly_accessible") is True:
        yield Detection(
            message="Database instance is reachable from the public internet.",
            fix=(
                "Set publicly_accessible = false and access the database "
                "through private subnets (VPN, bastion, or SSM port forwarding)."
            ),
            fix_code="publicly_accessible = false",
        )


@rule(
    id="SEC005",
    title="Database storage is not encrypted",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description="storage_encrypted is false or unset, so data at rest is unencrypted.",
    resource_types=("aws_db_instance",),
    references=(
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
    ),
)
def rds_unencrypted(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("storage_encrypted") is not True:
        yield Detection(
            message="RDS storage encryption is disabled (storage_encrypted is not true).",
            fix=(
                "Set storage_encrypted = true (requires re-creating the "
                "instance — plan a snapshot/restore migration)."
            ),
            fix_code="storage_encrypted = true",
        )


@rule(
    id="SEC006",
    title="EBS volume is not encrypted",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description="The EBS volume does not enable encryption at rest.",
    resource_types=("aws_ebs_volume",),
    references=("https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",),
)
def ebs_unencrypted(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("encrypted") is not True:
        yield Detection(
            message="EBS volume is unencrypted (encrypted is not true).",
            fix="Set encrypted = true; consider enabling EBS encryption by default account-wide.",
            fix_code="encrypted = true",
        )


_WILDCARD_ACTION = re.compile(r'"Action"\s*:\s*"\*"')
_WILDCARD_RESOURCE = re.compile(r'"Resource"\s*:\s*"\*"')


def _policy_is_star_star(policy: object) -> bool:
    """Detect Action:* together with Resource:* in an IAM policy document."""
    if not isinstance(policy, str):
        return False
    try:
        doc = json.loads(policy)
    except ValueError:
        # jsonencode()/heredoc edge cases: fall back to a textual check
        return bool(_WILDCARD_ACTION.search(policy) and _WILDCARD_RESOURCE.search(policy))
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


@rule(
    id="SEC007",
    title="IAM policy allows * on *",
    category=Category.SECURITY,
    severity=Severity.CRITICAL,
    description=(
        "An IAM policy grants every action on every resource — full account "
        "admin. One leaked credential becomes a full compromise."
    ),
    resource_types=(
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    ),
    references=(
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
    ),
)
def iam_wildcard(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if _policy_is_star_star(res.body.get("policy")):
        yield Detection(
            message='IAM policy allows "Action": "*" on "Resource": "*" (full admin).',
            fix=(
                "Scope the policy to the specific actions and resource ARNs "
                "the workload needs (least privilege). Use IAM Access "
                "Analyzer to generate a policy from real activity."
            ),
        )


_SECRET_ATTRS = (
    "password",
    "master_password",
    "secret",
    "secret_key",
    "api_key",
    "token",
    "private_key",
)


@rule(
    id="SEC008",
    title="Hardcoded secret in configuration",
    category=Category.SECURITY,
    severity=Severity.CRITICAL,
    description=(
        "A credential-looking attribute holds a literal value. Anything "
        "committed to Git should be assumed leaked."
    ),
    references=(
        "https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables",
    ),
)
def hardcoded_secret(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for attr, value in res.body.items():
        if attr not in _SECRET_ATTRS:
            continue
        if isinstance(value, str) and value and not is_interpolation(value):
            yield Detection(
                message=(
                    f"Attribute '{attr}' contains a hardcoded literal secret."
                ),
                fix=(
                    "Move the value to a secrets manager (AWS Secrets Manager / "
                    "SSM Parameter Store) or a sensitive Terraform variable, "
                    "then rotate the exposed credential — treat it as leaked."
                ),
                fix_code=(
                    f"{attr} = var.{attr}  "
                    f'# declare as: variable "{attr}" {{ sensitive = true }}'
                ),
            )


@rule(
    id="SEC009",
    title="EC2 instance does not require IMDSv2",
    category=Category.SECURITY,
    severity=Severity.MEDIUM,
    description=(
        "Without http_tokens = \"required\", the instance accepts IMDSv1 "
        "requests, enabling SSRF credential-stealing attacks."
    ),
    resource_types=("aws_instance", "aws_launch_template"),
    references=(
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    ),
)
def imdsv1_allowed(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    options = blocks(res.body, "metadata_options")
    tokens = options[0].get("http_tokens") if options else None
    if tokens != "required":
        yield Detection(
            message="Instance metadata service allows IMDSv1 (http_tokens is not 'required').",
            fix="Require IMDSv2 by setting metadata_options.http_tokens = \"required\".",
            fix_code='metadata_options {\n  http_tokens = "required"\n}',
        )


@rule(
    id="SEC010",
    title="Load balancer listener speaks plaintext HTTP",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "The listener accepts unencrypted HTTP. Credentials, cookies and "
        "session tokens crossing it are readable in transit."
    ),
    resource_types=("aws_lb_listener", "aws_alb_listener"),
    references=(
        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
    ),
)
def plaintext_listener(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if str(res.body.get("protocol", "")).upper() != "HTTP":
        return
    actions = blocks(res.body, "default_action")
    if any(a.get("type") == "redirect" for a in actions):
        return  # an HTTP->HTTPS redirect listener is the correct pattern
    yield Detection(
        message="Listener serves traffic over unencrypted HTTP with no redirect to HTTPS.",
        fix=(
            "Terminate TLS on the load balancer (HTTPS listener with an ACM "
            "certificate) and keep port 80 only as a redirect to 443."
        ),
        fix_code=(
            'protocol = "HTTPS"\n'
            'port     = 443\n'
            "certificate_arn = aws_acm_certificate.this.arn"
        ),
    )
