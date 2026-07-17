"""Remediation proposal — the Trust Ladder's first rung above read-only.

Renders a scan into a ready-to-review change proposal: per-file patches
with rationale, suitable for a pull-request description or `gh pr comment
--body-file`. Cairn drafts; a human reviews and merges. Nothing here
modifies the repository.
"""

from __future__ import annotations

from collections import defaultdict

from cairn.engine import ScanResult
from cairn.findings import Finding


def render_proposal(
    result: ScanResult,
    explanations: dict[Finding, str] | None = None,
    color: bool = False,  # unused; uniform reporter signature
) -> str:
    """Render a review-ready remediation proposal (per-file patches; changes nothing)."""
    explanations = explanations or {}
    lines = ["# Cairn remediation proposal", ""]
    if not result.findings:
        lines.append("Nothing to propose — the scan is clean.")
        return "\n".join(lines)

    savings = result.estimated_monthly_savings
    lines.append(
        f"{len(result.findings)} finding(s) in `{result.target}`"
        + (f"; applying the fixes below recovers an estimated "
           f"**~${savings:,.2f}/month**" if savings else "")
        + "."
    )
    lines.append("")
    lines.append(
        "Cairn drafted these changes; a human reviews and applies them. "
        "Fixes are ordered by severity within each file."
    )

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        by_file[finding.file].append(finding)

    for file in sorted(by_file):
        lines.extend(["", f"## `{file}`", ""])
        for finding in by_file[file]:
            lines.append(
                f"### {finding.rule_id} · {finding.severity.value} · `{finding.address}`"
            )
            lines.append("")
            lines.append(f"{finding.message}")
            lines.append("")
            lines.append(f"**Change:** {finding.fix}")
            if finding.fix_code:
                lines.extend(["", "```hcl", finding.fix_code, "```"])
            explanation = explanations.get(finding)
            if explanation:
                lines.extend(["", f"> {explanation}"])
            lines.append("")

    if result.trade_offs:
        lines.append("## Sequencing")
        lines.append("")
        for trade_off in result.trade_offs:
            lines.append(f"- `{trade_off.address}`: {trade_off.note}")
        lines.append("")

    lines.append("---")
    lines.append(
        "Review checklist: fixes match your environment's intent · plan "
        "output reviewed (`terraform plan`) · security fixes sequenced "
        "before right-sizing on shared resources."
    )
    return "\n".join(lines)
