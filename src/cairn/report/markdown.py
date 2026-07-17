"""Markdown report — pasteable into a PR description or ticket."""

from __future__ import annotations

from cairn.engine import ScanResult
from cairn.findings import Finding

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def render_markdown(
    result: ScanResult,
    explanations: dict[Finding, str] | None = None,
    color: bool = False,  # unused; uniform reporter signature
) -> str:
    """Render a scan result as Markdown suitable for a PR description or ticket."""
    explanations = explanations or {}
    lines = ["# Cairn scan report", ""]
    lines.append(
        f"**Target:** `{result.target}` · {result.resources_scanned} resources · "
        f"{result.files_scanned} files · {result.duration_seconds:.2f}s"
    )
    lines.append("")

    if not result.findings:
        lines.append("✅ **No findings. Clean.**")
        return "\n".join(lines)

    savings = result.estimated_monthly_savings
    lines.append(
        f"**{len(result.findings)} finding(s)**"
        + (f" · estimated recoverable spend **~${savings:,.2f}/month**" if savings else "")
    )
    lines.append("")
    lines.append("| # | Severity | Category | Resource | Problem | Est. $/mo |")
    lines.append("|---|----------|----------|----------|---------|-----------|")
    for index, finding in enumerate(result.findings, 1):
        emoji = _SEVERITY_EMOJI.get(finding.severity.value, "")
        cost = f"${finding.monthly_cost:,.2f}" if finding.monthly_cost is not None else "—"
        problem = finding.message.replace("|", "\\|")
        lines.append(
            f"| {index} | {emoji} {finding.severity.value} | {finding.category.value} "
            f"| `{finding.address}` | {problem} | {cost} |"
        )
    lines.append("")

    lines.append("## Fixes")
    lines.append("")
    for index, finding in enumerate(result.findings, 1):
        lines.append(f"### {index}. `{finding.address}` — {finding.rule_id}")
        lines.append("")
        lines.append(finding.fix)
        if finding.fix_code:
            lines.extend(["", "```hcl", finding.fix_code, "```"])
        explanation = explanations.get(finding)
        if explanation:
            lines.extend(["", f"> {explanation}"])
        lines.append("")

    if result.trade_offs:
        lines.append("## ⚖ Trade-offs")
        lines.append("")
        for trade_off in result.trade_offs:
            joined = " + ".join(trade_off.categories)
            lines.append(f"- **`{trade_off.address}`** ({joined}): {trade_off.note}")
        lines.append("")

    return "\n".join(lines)
