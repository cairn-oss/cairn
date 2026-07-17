"""Pre-merge cost simulation: what does this change do to the bill?

Estimates use the same offline price book as the scanner
(:mod:`cairn.pricing`) — indicative on-demand figures that put a dollar
sign on a diff at review time, not billing-grade accounting. Resources the
book cannot price are listed as unpriced rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cairn import pricing
from cairn.terraform import Resource, parse_path


def estimate_resource(resource: Resource) -> float | None:
    """Monthly USD estimate for one resource, or None when unpriceable."""
    body = resource.body
    if resource.type == "aws_instance":
        itype = body.get("instance_type")
        return pricing.ec2_monthly(itype) if isinstance(itype, str) else None
    if resource.type == "aws_db_instance":
        iclass = body.get("instance_class")
        base = pricing.rds_monthly(iclass) if isinstance(iclass, str) else None
        if base is not None and body.get("multi_az") is True:
            return round(base * 2, 2)
        return base
    if resource.type == "aws_ebs_volume":
        size = body.get("size")
        vtype = str(body.get("type", "gp2"))
        if isinstance(size, int | float):
            return round(size * pricing.EBS_GB_MONTH.get(vtype, pricing.EBS_GB_MONTH["gp2"]), 2)
    return None


@dataclass
class CostDiff:
    """Estimated monthly cost movement between two configurations."""

    old_total: float = 0.0
    new_total: float = 0.0
    added: list[tuple[str, float]] = field(default_factory=list)
    removed: list[tuple[str, float]] = field(default_factory=list)
    changed: list[tuple[str, float, float]] = field(default_factory=list)
    unpriced: list[str] = field(default_factory=list)

    @property
    def delta(self) -> float:
        return round(self.new_total - self.old_total, 2)


def _priced(path: Path) -> tuple[dict[str, float], list[str]]:
    priced: dict[str, float] = {}
    unpriced: list[str] = []
    for resource in parse_path(path).resources:
        estimate = estimate_resource(resource)
        if estimate is None:
            unpriced.append(resource.address)
        else:
            priced[resource.address] = estimate
    return priced, unpriced


def diff_costs(old_path: Path, new_path: Path) -> CostDiff:
    """Estimate the monthly cost movement between two Terraform configurations."""
    old, old_unpriced = _priced(old_path)
    new, new_unpriced = _priced(new_path)
    result = CostDiff(
        old_total=round(sum(old.values()), 2),
        new_total=round(sum(new.values()), 2),
        unpriced=sorted(set(old_unpriced) | set(new_unpriced)),
    )
    for address in sorted(set(old) | set(new)):
        before, after = old.get(address), new.get(address)
        if before is None and after is not None:
            result.added.append((address, after))
        elif before is not None and after is None:
            result.removed.append((address, before))
        elif before is not None and after is not None and before != after:
            result.changed.append((address, before, after))
    return result


def render_cost_diff(diff: CostDiff, budget_limit: float | None) -> str:
    """Render a cost diff as text, flagging a breach of *budget_limit* if set."""
    lines = ["Cairn cost simulation (estimated on-demand monthly cost):", ""]
    for address, cost in diff.added:
        lines.append(f"  + {address:<45} +${cost:,.2f}/mo")
    for address, cost in diff.removed:
        lines.append(f"  - {address:<45} -${cost:,.2f}/mo")
    for address, before, after in diff.changed:
        sign = "+" if after > before else "-"
        lines.append(
            f"  ~ {address:<45} ${before:,.2f} -> ${after:,.2f} "
            f"({sign}${abs(after - before):,.2f}/mo)"
        )
    if not (diff.added or diff.removed or diff.changed):
        lines.append("  no priced resources changed")
    lines.append("")
    sign = "+" if diff.delta >= 0 else ""
    lines.append(
        f"Total: ${diff.old_total:,.2f}/mo -> ${diff.new_total:,.2f}/mo "
        f"({sign}${diff.delta:,.2f}/mo)"
    )
    if diff.unpriced:
        lines.append(f"Unpriced resources (no estimate attempted): {len(diff.unpriced)}")
    if budget_limit is not None:
        verdict = "BREACHES" if diff.delta > budget_limit else "within"
        lines.append(
            f"Budget gate: change {verdict} the configured limit of "
            f"+${budget_limit:,.2f}/mo"
        )
    lines.append("Estimates from the bundled price book; see docs/pricing.md.")
    return "\n".join(lines)
