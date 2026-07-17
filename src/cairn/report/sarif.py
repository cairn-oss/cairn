"""SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers."""

from __future__ import annotations

import json

from cairn import __version__
from cairn.engine import ScanResult
from cairn.findings import Finding, Severity
from cairn.rules import all_rules

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: GitHub's security-severity property (CVSS-like scale).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(
    result: ScanResult,
    explanations: dict[Finding, str] | None = None,  # unused; uniform signature
    color: bool = False,  # unused; uniform reporter signature
) -> str:
    """Render a scan result as SARIF 2.1.0 for GitHub Code Scanning."""
    rules_meta = [
        {
            "id": rule.id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "helpUri": rule.references[0] if rule.references else
                "https://github.com/cairn-oss/cairn/blob/main/docs/rules.md",
            "properties": {
                "category": rule.category.value.lower(),
                "security-severity": _SECURITY_SEVERITY[rule.severity],
            },
        }
        for rule in all_rules()
    ]

    results = []
    for finding in result.findings:
        message = f"{finding.message} Fix: {finding.fix}"
        if finding.monthly_cost is not None:
            message += f" (estimated ~${finding.monthly_cost:,.2f}/month recoverable)"
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file.replace("\\", "/")},
                            "region": {"startLine": max(finding.line, 1)},
                        }
                    }
                ],
                "properties": {
                    "resource": finding.address,
                    "category": finding.category.value.lower(),
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cairn",
                        "informationUri": "https://github.com/cairn-oss/cairn",
                        "version": __version__,
                        "rules": rules_meta,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
