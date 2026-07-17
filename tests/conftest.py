"""Shared fixtures: parse HCL snippets and run the rule set over them."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from cairn.findings import Finding
from cairn.rules import all_rules
from cairn.rules.base import ScanContext
from cairn.terraform import Resource, parse_file

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"


@pytest.fixture
def make_resources(tmp_path: Path):
    """Parse an HCL snippet into Resources (asserts it parses cleanly)."""

    def _make(source: str) -> list[Resource]:
        file = tmp_path / "main.tf"
        file.write_text(textwrap.dedent(source), encoding="utf-8")
        parsed = parse_file(file)
        assert parsed.error is None, f"fixture failed to parse: {parsed.error}"
        return list(parsed.resources)

    return _make


@pytest.fixture
def run_rules(make_resources):
    """Run every registered rule over an HCL snippet; return findings."""

    def _run(source: str, required_tags: tuple[str, ...] = ()) -> list[Finding]:
        resources = make_resources(source)
        ctx = ScanContext(resources=tuple(resources), required_tags=required_tags)
        findings: list[Finding] = []
        for resource in resources:
            for rule in all_rules():
                if rule.applies_to(resource):
                    findings.extend(rule.run(resource, ctx))
        return findings

    return _run


def rule_ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings}
