"""Reporters: render a ScanResult for humans (console, markdown) and
machines (JSON, SARIF)."""

from cairn.report.console import render_console
from cairn.report.html import render_html
from cairn.report.json_report import render_json
from cairn.report.markdown import render_markdown
from cairn.report.proposal import render_proposal
from cairn.report.sarif import render_sarif

FORMATS = {
    "console": render_console,
    "html": render_html,
    "json": render_json,
    "sarif": render_sarif,
    "markdown": render_markdown,
}

__all__ = [
    "FORMATS",
    "render_console",
    "render_html",
    "render_json",
    "render_markdown",
    "render_proposal",
    "render_sarif",
]
