"""Built-in VMware vSphere rules (VS···) — the on-prem / private-cloud pack.

On-prem estates don't have per-hour cloud pricing, so this pack focuses on
security, reliability and governance — the disciplines that apply
everywhere. Cost findings are intentionally cloud-only.
"""

from __future__ import annotations

from collections.abc import Iterator

from cairn.findings import Category, Severity
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource


@rule(
    id="VS001",
    title="Virtual machine has no resource limits",
    category=Category.RELIABILITY,
    severity=Severity.MEDIUM,
    description=(
        "No CPU/memory reservation or limit is set, so one noisy VM can "
        "starve the host and its neighbours."
    ),
    resource_types=("vsphere_virtual_machine",),
    references=("https://docs.vmware.com/en/VMware-vSphere/index.html",),
)
def vm_no_limits(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    body = res.body
    limit_keys = ("cpu_reservation", "memory_reservation", "cpu_limit", "memory_limit")
    if not any(body.get(k) for k in limit_keys):
        yield Detection(
            message="VM has no CPU/memory reservation or limit.",
            fix="Set memory_reservation and cpu/memory limits so one VM can't starve the host.",
        )


@rule(
    id="VS002",
    title="Virtual disk is not thin-provisioned",
    category=Category.COST,
    severity=Severity.LOW,
    description=(
        "Eager/thick provisioning reserves the full disk up front. On shared "
        "datastores thin provisioning reclaims idle capacity."
    ),
    resource_types=("vsphere_virtual_machine",),
    references=("https://docs.vmware.com/en/VMware-vSphere/index.html",),
)
def thick_disk(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for disk in _disks(res):
        if disk.get("thin_provisioned") is False:
            yield Detection(
                message=f"Disk '{disk.get('label', '?')}' is thick-provisioned.",
                fix="Set thin_provisioned = true to reclaim idle datastore capacity.",
                fix_code="thin_provisioned = true",
            )
            return


@rule(
    id="VS003",
    title="VM has no annotation / owner",
    category=Category.GOVERNANCE,
    severity=Severity.LOW,
    description="No annotation is set, so ownership and purpose are untrackable.",
    resource_types=("vsphere_virtual_machine",),
    references=("https://docs.vmware.com/en/VMware-vSphere/index.html",),
)
def no_annotation(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if not str(res.body.get("annotation", "")).strip():
        yield Detection(
            message="VM has no annotation — ownership and purpose are untrackable.",
            fix="Set an annotation recording owner, environment and purpose.",
            fix_code='annotation = "owner=platform; env=prod; purpose=..."',
        )


def _disks(res: Resource) -> list[dict[str, object]]:
    disk = res.body.get("disk")
    if isinstance(disk, dict):
        return [disk]
    if isinstance(disk, list):
        return [d for d in disk if isinstance(d, dict)]
    return []
