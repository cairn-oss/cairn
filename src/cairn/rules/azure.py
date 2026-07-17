"""Built-in Azure rules (AZ···). Mirrors the AWS families across the
network-exposure, encryption, cost and governance disciplines."""

from __future__ import annotations

from collections.abc import Iterator

from cairn import pricing
from cairn.findings import Category, Severity
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource

_OPEN = {"*", "0.0.0.0/0", "internet"}


@rule(
    id="AZ001",
    title="Network security group rule open to the internet",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description=(
        "An inbound NSG rule allows any source (*/Internet). SSH (22) and "
        "RDP (3389) exposure is rated CRITICAL."
    ),
    resource_types=("azurerm_network_security_rule",),
    references=(
        "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview",
    ),
)
def nsg_open(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    body = res.body
    if str(body.get("direction", "Inbound")) != "Inbound":
        return
    if str(body.get("access", "Allow")) != "Allow":
        return
    prefix = str(body.get("source_address_prefix", "")).lower()
    if prefix not in _OPEN:
        return
    port = str(body.get("destination_port_range", "*"))
    admin = port in ("22", "3389", "*")
    yield Detection(
        message=f"NSG rule allows inbound from any source on port {port}.",
        severity=Severity.CRITICAL if admin else None,
        fix="Restrict source_address_prefix to known ranges or a service tag.",
        fix_code='source_address_prefix = "10.0.0.0/8"',
    )


@rule(
    id="AZ002",
    title="Storage account allows public blob access",
    category=Category.SECURITY,
    severity=Severity.HIGH,
    description="allow_nested_items_to_be_public / allow_blob_public_access is enabled.",
    resource_types=("azurerm_storage_account",),
    references=("https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",),
)
def storage_public(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    body = res.body
    public = (
        body.get("allow_nested_items_to_be_public") is True
        or body.get("allow_blob_public_access") is True
    )
    if public:
        yield Detection(
            message="Storage account permits anonymous public blob access.",
            fix="Set allow_nested_items_to_be_public = false.",
            fix_code="allow_nested_items_to_be_public = false",
        )


@rule(
    id="AZ003",
    title="SQL server allows public network access",
    category=Category.SECURITY,
    severity=Severity.CRITICAL,
    description="public_network_access_enabled is true, exposing the database endpoint.",
    resource_types=("azurerm_mssql_server", "azurerm_postgresql_server"),
    references=("https://learn.microsoft.com/azure/azure-sql/database/network-access-controls-overview",),
)
def sql_public(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("public_network_access_enabled") is True:
        yield Detection(
            message="Database server allows public network access.",
            fix="Set public_network_access_enabled = false; use a private endpoint.",
            fix_code="public_network_access_enabled = false",
        )


@rule(
    id="AZ004",
    title="Managed disk is not encrypted with a customer key",
    category=Category.SECURITY,
    severity=Severity.MEDIUM,
    description="No disk_encryption_set_id is set, so the disk uses only platform-managed keys.",
    resource_types=("azurerm_managed_disk",),
    references=("https://learn.microsoft.com/azure/virtual-machines/disk-encryption",),
)
def disk_unencrypted(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if not res.body.get("disk_encryption_set_id"):
        yield Detection(
            message="Managed disk has no customer-managed encryption key.",
            fix="Attach a disk_encryption_set_id for customer-managed key control.",
        )


@rule(
    id="AZ005",
    title="Oversized virtual machine",
    category=Category.COST,
    severity=Severity.MEDIUM,
    description="The VM size is in a large SKU family and is likely over-provisioned.",
    resource_types=("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"),
    references=("https://learn.microsoft.com/azure/virtual-machines/sizes",),
)
def oversized_vm(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    size = str(res.body.get("size", ""))
    if any(marker in size for marker in ("16", "32", "48", "64", "_D8", "_E8", "_F8")):
        cost = pricing.AZURE_VM_MONTHLY.get(size)
        note = f" (~${cost:,.0f}/month)" if cost else ""
        yield Detection(
            message=f"VM size '{size}' is large{note} and likely over-provisioned.",
            fix="Right-size from Azure Monitor metrics; consider a smaller SKU or a savings plan.",
            monthly_cost=cost,
        )


@rule(
    id="AZ006",
    title="Resource has no tags",
    category=Category.GOVERNANCE,
    severity=Severity.LOW,
    description="Untagged Azure resources break cost attribution and ownership.",
    resource_types=(
        "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine",
        "azurerm_storage_account", "azurerm_managed_disk", "azurerm_mssql_server",
    ),
    references=("https://learn.microsoft.com/azure/azure-resource-manager/management/tag-resources",),
)
def missing_tags(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    tags = res.body.get("tags")
    if not (isinstance(tags, dict) and tags):
        yield Detection(
            message="Resource has no tags — cost allocation and ownership are untrackable.",
            fix="Add tags (at least environment and owner).",
            fix_code='tags = {\n  environment = "prod"\n  owner       = "platform"\n}',
        )
