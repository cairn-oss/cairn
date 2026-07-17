"""Built-in FinOps rules (COST···).

Cost findings carry a ``monthly_cost`` estimate: the approximate USD/month
recovered by applying the fix. Estimates come from the bundled offline
price book (:mod:`cairn.pricing`) — indicative, not billing-grade.
"""

from __future__ import annotations

from collections.abc import Iterator

from cairn import pricing
from cairn.findings import Category, Severity
from cairn.rules._helpers import references_resource
from cairn.rules.base import Detection, ScanContext, rule
from cairn.terraform import Resource


def _size_suffix(instance_type: str) -> str:
    return instance_type.split(".", 1)[1] if "." in instance_type else ""


@rule(
    id="COST001",
    title="Oversized EC2 instance",
    category=Category.COST,
    severity=Severity.MEDIUM,
    description=(
        "The instance type is in a very large size class. Most workloads "
        "run well below 20% utilization; right-sizing is the highest-yield "
        "FinOps action."
    ),
    resource_types=("aws_instance",),
    references=("https://aws.amazon.com/aws-cost-management/aws-cost-optimization/right-sizing/",),
)
def oversized_instance(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    itype = res.body.get("instance_type")
    if not isinstance(itype, str) or not _size_suffix(itype).startswith(pricing.OVERSIZED_PREFIXES):
        return
    current = pricing.ec2_monthly(itype)
    family = itype.split(".", 1)[0]
    suggested = f"{family}.xlarge"
    suggested_cost = pricing.ec2_monthly(suggested)
    waste = (
        round(current - suggested_cost, 2)
        if current is not None and suggested_cost is not None
        else None
    )
    cost_note = f" (~${current:,.0f}/month on-demand)" if current is not None else ""
    yield Detection(
        message=f"Instance type '{itype}' is very large{cost_note} and likely over-provisioned.",
        fix=(
            f"Verify utilization (CloudWatch CPU/memory over 2+ weeks); a "
            f"smaller type such as {suggested} often carries the load at a "
            f"fraction of the cost. If sustained load is real, consider a "
            f"savings plan instead of on-demand."
        ),
        fix_code=f'instance_type = "{suggested}"',
        monthly_cost=waste,
    )


@rule(
    id="COST002",
    title="gp2 volume — gp3 is cheaper and faster",
    category=Category.COST,
    severity=Severity.LOW,
    description=(
        "gp3 offers the same baseline performance as gp2 at ~20% lower "
        "GB-month price, with independently provisionable IOPS."
    ),
    resource_types=("aws_ebs_volume",),
    references=("https://aws.amazon.com/ebs/general-purpose/",),
)
def gp2_volume(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("type") != "gp2":
        return
    size = res.body.get("size")
    waste = None
    if isinstance(size, int | float):
        waste = round(size * (pricing.EBS_GB_MONTH["gp2"] - pricing.EBS_GB_MONTH["gp3"]), 2)
    yield Detection(
        message="EBS volume uses gp2; gp3 is ~20% cheaper for the same performance.",
        fix="Migrate the volume type to gp3 (online operation, no downtime).",
        fix_code='type = "gp3"',
        monthly_cost=waste,
    )


@rule(
    id="COST003",
    title="Unassociated Elastic IP",
    category=Category.COST,
    severity=Severity.LOW,
    description=(
        "An Elastic IP that is not attached to anything is billed hourly "
        "for doing nothing."
    ),
    resource_types=("aws_eip",),
    references=("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",),
)
def idle_eip(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    if res.body.get("instance") or res.body.get("network_interface"):
        return
    for assoc in ctx.by_type("aws_eip_association"):
        if references_resource(assoc.body.get("allocation_id"), res.address):
            return
    yield Detection(
        message="Elastic IP is not associated with any instance or network interface.",
        fix="Associate the EIP with a resource or release it.",
        monthly_cost=round(pricing.IDLE_EIP_HOURLY * pricing.HOURS_PER_MONTH, 2),
    )


@rule(
    id="COST004",
    title="Oversized RDS instance class",
    category=Category.COST,
    severity=Severity.MEDIUM,
    description="The database instance class is in a very large size class.",
    resource_types=("aws_db_instance",),
    references=("https://aws.amazon.com/rds/instance-types/",),
)
def oversized_rds(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    iclass = res.body.get("instance_class")
    if not isinstance(iclass, str):
        return
    suffix = iclass.rsplit(".", 1)[-1]
    if not suffix.startswith(("2xlarge", *pricing.OVERSIZED_PREFIXES)):
        return
    current = pricing.rds_monthly(iclass)
    family = iclass.rsplit(".", 1)[0]  # e.g. db.m5
    suggested = f"{family}.large"
    suggested_cost = pricing.rds_monthly(suggested)
    waste = (
        round(current - suggested_cost, 2)
        if current is not None and suggested_cost is not None
        else None
    )
    cost_note = f" (~${current:,.0f}/month single-AZ on-demand)" if current is not None else ""
    yield Detection(
        message=f"RDS instance class '{iclass}' is very large{cost_note}.",
        fix=(
            f"Check Performance Insights; if headroom is consistently high, "
            f"step down (e.g. {suggested}) or move to Aurora Serverless for "
            f"spiky workloads."
        ),
        fix_code=f'instance_class = "{suggested}"',
        monthly_cost=waste,
    )


@rule(
    id="COST005",
    title="Previous-generation instance type",
    category=Category.COST,
    severity=Severity.LOW,
    description=(
        "Previous-generation families (t2/m4/c4/r4) cost more than their "
        "modern equivalents for less performance."
    ),
    resource_types=("aws_instance",),
    references=("https://aws.amazon.com/ec2/previous-generation/",),
)
def old_generation(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    itype = res.body.get("instance_type")
    if not isinstance(itype, str) or "." not in itype:
        return
    family, size = itype.split(".", 1)
    upgrade_family = pricing.OLD_GENERATION_UPGRADES.get(family)
    if upgrade_family is None:
        return
    suggested = f"{upgrade_family}.{size}"
    current = pricing.ec2_monthly(itype)
    upgraded = pricing.ec2_monthly(suggested)
    waste = round(current - upgraded, 2) if current is not None and upgraded is not None else None
    yield Detection(
        message=(
            f"Instance type '{itype}' is previous-generation; "
            f"'{suggested}' is cheaper and faster."
        ),
        fix=f"Move to the current generation ({suggested}); same workload, lower price.",
        fix_code=f'instance_type = "{suggested}"',
        monthly_cost=waste,
    )


@rule(
    id="COST006",
    title="EBS volume attached to nothing",
    category=Category.COST,
    severity=Severity.LOW,
    description=(
        "A volume with no aws_volume_attachment referencing it is billed "
        "every month for storing data nothing reads."
    ),
    resource_types=("aws_ebs_volume",),
    references=("https://aws.amazon.com/ebs/pricing/",),
)
def unattached_volume(res: Resource, ctx: ScanContext) -> Iterator[Detection]:
    for attachment in ctx.by_type("aws_volume_attachment"):
        if references_resource(attachment.body.get("volume_id"), res.address):
            return
    size = res.body.get("size")
    vtype = str(res.body.get("type", "gp2"))
    waste = None
    if isinstance(size, int | float):
        waste = round(size * pricing.EBS_GB_MONTH.get(vtype, pricing.EBS_GB_MONTH["gp2"]), 2)
    yield Detection(
        message="EBS volume is not attached to any instance.",
        fix="Attach the volume, snapshot-and-delete it, or delete it outright.",
        monthly_cost=waste,
    )
