"""Built-in Google Cloud rules (GCP···)."""

from __future__ import annotations

from collections.abc import Iterator

from cairn import pricing
from cairn.findings import Category, Severity
from cairn.rules._helpers import blocks
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource


@rule(
    id="GCP001",
    title="Firewall rule open to the internet",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "A firewall rule allows ingress from 0.0.0.0/0. SSH (22) and RDP "
        "(3389) exposure is rated CRITICAL."
    ),
    resource_types=("google_compute_firewall",),
    references=("https://cloud.google.com/vpc/docs/firewalls",),
)
def firewall_open(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    ranges = res.body.get("source_ranges") or []
    if isinstance(ranges, str):
        ranges = [ranges]
    if "0.0.0.0/0" not in ranges:
        return
    ports: list[str] = []
    for allow in blocks(res.body, "allow"):
        p = allow.get("ports") or []
        ports.extend(p if isinstance(p, list) else [p])
    admin = any(str(p) in ("22", "3389") for p in ports) or not ports
    port_list = ", ".join(map(str, ports)) or "all"
    yield Detection(
        message=f"Firewall allows ingress from 0.0.0.0/0 (ports: {port_list}).",
        severity=Severity.CRITICAL if admin else None,
        fix="Restrict source_ranges to known CIDRs or use IAP for admin access.",
        fix_code='source_ranges = ["10.0.0.0/8"]',
    )


@rule(
    id="GCP002",
    title="Storage bucket is publicly accessible",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description="Uniform bucket-level access is disabled, allowing per-object public ACLs.",
    resource_types=("google_storage_bucket",),
    references=("https://cloud.google.com/storage/docs/uniform-bucket-level-access",),
)
def bucket_public(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("uniform_bucket_level_access") is not True:
        yield Detection(
            message="Bucket does not enforce uniform bucket-level access.",
            fix="Set uniform_bucket_level_access = true to disable per-object public ACLs.",
            fix_code="uniform_bucket_level_access = true",
        )


@rule(
    id="GCP003",
    title="Cloud SQL instance has a public IP",
    category=Category.SECURITY,
    severity=Severity.CRITICAL,
    description="ipv4_enabled is true, exposing the database on a public IP.",
    resource_types=("google_sql_database_instance",),
    references=("https://cloud.google.com/sql/docs/mysql/configure-private-ip",),
)
def sql_public_ip(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for settings in blocks(res.body, "settings"):
        for ip_cfg in blocks(settings, "ip_configuration"):
            if ip_cfg.get("ipv4_enabled") is True:
                yield Detection(
                    message="Cloud SQL instance is reachable on a public IP.",
                    fix="Set ipv4_enabled = false and use private IP / VPC peering.",
                    fix_code="ipv4_enabled = false",
                )


@rule(
    id="GCP004",
    title="Compute instance without Shielded VM",
    category=Category.SECURITY,
    severity=Severity.MEDIUM,
    description="shielded_instance_config with secure boot is not enabled.",
    resource_types=("google_compute_instance",),
    references=("https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",),
)
def no_shielded_vm(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    shielded = blocks(res.body, "shielded_instance_config")
    if not shielded or shielded[0].get("enable_secure_boot") is not True:
        yield Detection(
            message="Compute instance does not enable Shielded VM secure boot.",
            fix="Add shielded_instance_config { enable_secure_boot = true }.",
            fix_code="shielded_instance_config {\n  enable_secure_boot = true\n}",
        )


@rule(
    id="GCP005",
    title="Oversized machine type",
    category=Category.COST,
    severity=Severity.MEDIUM,
    description="The machine type is in a large class and is likely over-provisioned.",
    resource_types=("google_compute_instance",),
    references=("https://cloud.google.com/compute/docs/machine-resource",),
)
def oversized_machine(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    mt = str(res.body.get("machine_type", ""))
    tail = mt.rsplit("-", 1)[-1]
    if tail.isdigit() and int(tail) >= 16:
        cost = pricing.GCP_MACHINE_MONTHLY.get(mt)
        note = f" (~${cost:,.0f}/month)" if cost else ""
        yield Detection(
            message=(
                f"Machine type '{mt}' is large ({tail} vCPUs){note} "
                "and likely over-provisioned."
            ),
            fix="Right-size from monitoring; consider a committed-use discount if load is steady.",
            monthly_cost=cost,
        )


@rule(
    id="GCP006",
    title="Resource has no labels",
    category=Category.GOVERNANCE,
    severity=Severity.LOW,
    description="Unlabeled GCP resources break cost attribution and ownership.",
    resource_types=(
        "google_compute_instance",
        "google_storage_bucket",
        "google_sql_database_instance",
    ),
    references=("https://cloud.google.com/resource-manager/docs/creating-managing-labels",),
)
def missing_labels(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    labels = res.body.get("labels")
    if not (isinstance(labels, dict) and labels):
        yield Detection(
            message="Resource has no labels — cost allocation and ownership are untrackable.",
            fix="Add labels (at least environment and owner).",
            fix_code='labels = {\n  environment = "prod"\n  owner       = "platform"\n}',
        )
