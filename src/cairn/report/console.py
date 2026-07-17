"""Human console output — the product's first impression.

Findings are grouped and ranked, dollar figures ride along, and
cross-discipline trade-offs are called out explicitly (the fusion demo).
"""

from __future__ import annotations

from cairn.engine import ScanResult
from cairn.findings import Finding, Severity

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",  # bright red
    Severity.HIGH: "\033[31m",      # red
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.LOW: "\033[36m",       # cyan
    Severity.INFO: "\033[37m",      # grey
}


def _paint(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def _finding_block(
    index: int, finding: Finding, explanation: str | None, color: bool
) -> list[str]:
    sev = _paint(
        f"[{finding.severity.value}/{finding.category.value}]",
        _SEVERITY_COLOR[finding.severity] + _BOLD,
        color,
    )
    location = f"{finding.file}:{finding.line}" if finding.line else finding.file
    lines = [
        f"{index}. {sev} {finding.address}  {_paint(f'({finding.rule_id})', _DIM, color)}",
        f"   at:      {location}",
        f"   problem: {finding.message}",
        f"   fix:     {finding.fix}",
    ]
    if finding.monthly_cost is not None:
        lines.append(f"   saves:   ~${finding.monthly_cost:,.2f}/month (estimate)")
    if finding.blast_radius:
        shown = ", ".join(finding.blast_radius[:5])
        extra = f" (+{len(finding.blast_radius) - 5} more)" if len(finding.blast_radius) > 5 else ""
        lines.append(f"   blast:   {len(finding.blast_radius)} dependent(s): {shown}{extra}")
    if finding.fix_code:
        snippet = "\n".join(f"     {ln}" for ln in finding.fix_code.splitlines())
        lines.append(f"   patch:\n{snippet}")
    if explanation:
        wrapped = "\n".join(f"     {ln}" for ln in explanation.splitlines())
        lines.append(f"   cairn says:\n{wrapped}")
    lines.append("")
    return lines


def render_console(
    result: ScanResult,
    explanations: dict[Finding, str] | None = None,
    color: bool = False,
) -> str:
    """Render a scan result as human-readable console text (ANSI when *color*)."""
    explanations = explanations or {}
    out: list[str] = []

    if not result.findings:
        if result.fully_covered:
            out.append(
                f"Cairn scanned {result.resources_scanned} resource(s) across "
                f"{result.files_scanned} file(s) in {result.duration_seconds:.2f}s "
                f"— no findings. Clean."
            )
        else:
            # Honesty: don't call a scan "Clean" when resources went unchecked.
            out.append(
                f"Cairn checked {result.covered_resources} of "
                f"{result.resources_scanned} resource(s) across "
                f"{result.files_scanned} file(s) in {result.duration_seconds:.2f}s "
                f"— no findings in the checked resources."
            )
    else:
        by_cat = result.counts_by_category
        summary = ", ".join(f"{count} {cat.lower()}" for cat, count in sorted(by_cat.items()))
        out.append(
            _paint(
                f"Cairn found {len(result.findings)} issue(s) in "
                f"{result.target} ({summary}):",
                _BOLD,
                color,
            )
        )
        out.append("")
        for index, finding in enumerate(result.findings, 1):
            out.extend(_finding_block(index, finding, explanations.get(finding), color))

    if result.trade_offs:
        out.append(_paint("Trade-offs (cost x risk on the same resource):", _BOLD, color))
        for trade_off in result.trade_offs:
            out.append(f"  ⚖ {trade_off.address} [{' + '.join(trade_off.categories)}]")
            out.append(f"    {trade_off.note}")
        out.append("")

    if result.suppressed:
        out.append(
            _paint(
                f"{len(result.suppressed)} finding(s) suppressed by inline "
                "cairn:ignore markers (reasons recorded in JSON output).",
                _DIM,
                color,
            )
        )
        out.append("")

    if result.warnings:
        out.append(_paint("Warnings:", _BOLD, color))
        for warning in result.warnings:
            out.append(f"  ! {warning}")
        out.append("")

    if result.parse_errors:
        out.append(_paint("Files skipped (parse errors):", _BOLD, color))
        for error in result.parse_errors:
            out.append(f"  ! {error.file}: {error.message}")
        out.append("")

    if result.uncovered:
        types = ", ".join(result.uncovered_types[:8])
        extra = (
            f" (+{len(result.uncovered_types) - 8} more types)"
            if len(result.uncovered_types) > 8
            else ""
        )
        out.append(
            _paint(
                f"Not scanned: {len(result.uncovered)} resource(s) of "
                f"{len(result.uncovered_types)} type(s) have no rules yet "
                "- parsed but not checked (a coverage gap, not a clean result).",
                _BOLD,
                color,
            )
        )
        out.append(_paint(f"  types: {types}{extra}", _DIM, color))
        out.append(
            _paint(
                "  Cairn covers AWS, Azure, GCP, Kubernetes and vSphere. "
                "Run `cairn providers` for coverage; contribute a rule to "
                "close a gap (CONTRIBUTING.md).",
                _DIM,
                color,
            )
        )
        out.append("")

    savings = result.estimated_monthly_savings
    if savings:
        out.append(
            _paint(f"Estimated recoverable spend: ~${savings:,.2f}/month", _BOLD, color)
        )
    out.append(
        _paint(
            f"{result.resources_scanned} resource(s), {result.files_scanned} file(s), "
            f"{result.duration_seconds:.2f}s. Local-only scan; nothing left this machine.",
            _DIM,
            color,
        )
    )
    return "\n".join(out)
