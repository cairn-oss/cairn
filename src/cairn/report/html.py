"""Self-contained HTML report — a local dashboard with zero hosting.

One file, inline CSS, no JavaScript, no external assets: it can be opened
from disk, attached to a ticket, or archived, and it leaks nothing.
"""

from __future__ import annotations

import html as html_escape

from cairn import __version__
from cairn.engine import ScanResult
from cairn.findings import Finding

_SEVERITY_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#0e7490",
    "INFO": "#6b7280",
}

_CSS = """
body{font:15px/1.5 -apple-system,'Segoe UI',sans-serif;color:#1f2937;
     max-width:960px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.card{border:1px solid #e5e7eb;border-radius:8px;padding:.8rem 1.2rem;min-width:8rem}
.card b{display:block;font-size:1.4rem}
table{border-collapse:collapse;width:100%;font-size:.92em}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #e5e7eb;vertical-align:top}
.sev{font-weight:600;white-space:nowrap}
code{background:#f3f4f6;padding:.1em .35em;border-radius:4px;font-size:.92em}
pre{background:#f3f4f6;padding:.6rem;border-radius:6px;overflow-x:auto;font-size:.88em}
.muted{color:#6b7280;font-size:.9em}
.tradeoff{border-left:3px solid #d97706;padding:.4rem .8rem;margin:.5rem 0;background:#fffbeb}
"""


def _escape(value: str) -> str:
    return html_escape.escape(value, quote=True)


def render_html(
    result: ScanResult,
    explanations: dict[Finding, str] | None = None,
    color: bool = False,  # unused; uniform reporter signature
) -> str:
    """Render a scan result as one self-contained HTML file (no external assets)."""
    explanations = explanations or {}
    savings = result.estimated_monthly_savings
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>Cairn report — {_escape(result.target)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>Cairn scan report <span class='muted'>v{__version__}</span></h1>",
        f"<p class='muted'>Target <code>{_escape(result.target)}</code> · "
        f"{result.resources_scanned} resources · {result.files_scanned} files · "
        f"{result.duration_seconds:.2f}s · local-only scan</p>",
        "<div class='cards'>",
        f"<div class='card'><b>{len(result.findings)}</b>findings</div>",
        f"<div class='card'><b>${savings:,.0f}</b>est. recoverable /mo</div>",
        f"<div class='card'><b>{len(result.suppressed)}</b>suppressed</div>",
        f"<div class='card'><b>{len(result.trade_offs)}</b>trade-offs</div>",
        f"<div class='card'><b>{len(result.uncovered)}</b>unscanned</div>",
        "</div>",
    ]
    if result.uncovered:
        types = ", ".join(_escape(t) for t in result.uncovered_types[:12])
        parts.append(
            f"<div class='tradeoff'>Not scanned: {len(result.uncovered)} "
            f"resource(s) of {len(result.uncovered_types)} type(s) have no "
            f"rules yet — parsed but not checked (a coverage gap, not clean): "
            f"{types}</div>"
        )

    if not result.findings:
        parts.append("<p><strong>No findings. Clean.</strong></p>")
    else:
        parts.append("<h2>Findings</h2><table><tr><th>Severity</th><th>Resource</th>"
                     "<th>Problem &amp; fix</th><th>Est. $/mo</th></tr>")
        for finding in result.findings:
            colour = _SEVERITY_COLOR.get(finding.severity.value, "#6b7280")
            cost = f"${finding.monthly_cost:,.2f}" if finding.monthly_cost is not None else "—"
            fix_html = f"<div class='muted'>{_escape(finding.fix)}</div>"
            if finding.fix_code:
                fix_html += f"<pre>{_escape(finding.fix_code)}</pre>"
            if finding.blast_radius:
                deps = ", ".join(_escape(d) for d in finding.blast_radius[:8])
                fix_html += (
                    f"<div class='muted'>Blast radius: "
                    f"{len(finding.blast_radius)} dependent(s) — {deps}</div>"
                )
            explanation = explanations.get(finding)
            if explanation:
                fix_html += f"<div class='muted'><em>{_escape(explanation)}</em></div>"
            parts.append(
                f"<tr><td class='sev' style='color:{colour}'>{finding.severity.value}"
                f"<div class='muted'>{finding.rule_id}</div></td>"
                f"<td><code>{_escape(finding.address)}</code>"
                f"<div class='muted'>{_escape(finding.file)}:{finding.line}</div></td>"
                f"<td>{_escape(finding.message)}{fix_html}</td>"
                f"<td>{cost}</td></tr>"
            )
        parts.append("</table>")

    if result.trade_offs:
        parts.append("<h2>Trade-offs</h2>")
        for trade_off in result.trade_offs:
            parts.append(
                f"<div class='tradeoff'><code>{_escape(trade_off.address)}</code> "
                f"[{' + '.join(trade_off.categories)}]<br>{_escape(trade_off.note)}</div>"
            )

    if result.warnings:
        parts.append("<h2>Warnings</h2><ul>")
        parts.extend(f"<li class='muted'>{_escape(w)}</li>" for w in result.warnings)
        parts.append("</ul>")

    parts.append("<p class='muted'>Generated locally by Cairn. "
                 "Nothing left this machine.</p></body></html>")
    return "".join(parts)
