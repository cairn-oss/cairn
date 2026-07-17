"""Machine-readable JSON report (stable schema, versioned)."""

from __future__ import annotations

import json

from cairn import __version__
from cairn.engine import ScanResult
from cairn.findings import Finding

SCHEMA_VERSION = 2


def render_json(
    result: ScanResult,
    explanations: dict[Finding, str] | None = None,
    color: bool = False,  # unused; uniform reporter signature
) -> str:
    """Render a scan result as versioned JSON (schema_version 2)."""
    explanations = explanations or {}
    payload = {
        "schema_version": SCHEMA_VERSION,
        "cairn_version": __version__,
        "target": result.target,
        "summary": {
            "findings": len(result.findings),
            "by_severity": result.counts_by_severity,
            "by_category": result.counts_by_category,
            "estimated_monthly_savings_usd": result.estimated_monthly_savings,
            "files_scanned": result.files_scanned,
            "resources_scanned": result.resources_scanned,
            "covered_resources": result.covered_resources,
            "duration_seconds": round(result.duration_seconds, 3),
        },
        "coverage": {
            "fully_covered": result.fully_covered,
            "uncovered_count": len(result.uncovered),
            "uncovered_types": result.uncovered_types,
            "uncovered_resources": result.uncovered,
            "uncovered_by_provider": result.uncovered_by_provider,
        },
        "findings": [
            {**f.to_dict(), "explanation": explanations.get(f)} for f in result.findings
        ],
        "trade_offs": [
            {"resource": t.address, "categories": list(t.categories), "note": t.note}
            for t in result.trade_offs
        ],
        "suppressed": [
            {
                **s.finding.to_dict(),
                "suppression_reason": s.reason,
                "marker_line": s.marker_line,
            }
            for s in result.suppressed
        ],
        "warnings": list(result.warnings),
        "parse_errors": [
            {"file": e.file, "message": e.message} for e in result.parse_errors
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False)
