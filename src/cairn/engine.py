"""Scan orchestration: parse → detect → policy → reconcile.

The engine is pure application logic — no I/O besides reading Terraform
files — so it is directly unit-testable and reusable from the CLI, the
future CI action, and the future editor extension.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path

from cairn import kubernetes
from cairn.findings import Category, Finding, sort_findings
from cairn.graph import ResourceGraph, build_graph
from cairn.policy import Config
from cairn.providers import is_covered
from cairn.rules import all_rules, load_plugins
from cairn.rules.base import ScanContext
from cairn.terraform import ParseError, Suppression, parse_path


@dataclass(frozen=True)
class TradeOff:
    """Cost and security/reliability findings colliding on one resource.

    This is Cairn's differentiator surfaced as data: the scanner does
    not just emit siloed alerts, it tells the user when the cheap fix and
    the safe fix interact so one *decision* can be made.
    """

    address: str
    categories: tuple[str, ...]
    note: str


@dataclass(frozen=True)
class SuppressedFinding:
    """A finding dropped by an inline marker — kept for the audit trail."""

    finding: Finding
    reason: str
    marker_line: int


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[SuppressedFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    trade_offs: list[TradeOff] = field(default_factory=list)
    parse_errors: list[ParseError] = field(default_factory=list)
    files_scanned: int = 0
    resources_scanned: int = 0
    duration_seconds: float = 0.0
    graph: ResourceGraph | None = None
    #: Resource addresses that no rule was able to check (no coverage for
    #: their type). These are *unscanned*, not verified clean — the
    #: distinction that keeps "Clean" honest.
    uncovered: list[str] = field(default_factory=list)
    #: The distinct resource types among ``uncovered`` (for the summary).
    uncovered_types: list[str] = field(default_factory=list)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = Counter(f.severity.value for f in self.findings)
        return dict(counts)

    @property
    def counts_by_category(self) -> dict[str, int]:
        return dict(Counter(f.category.value for f in self.findings))

    @property
    def estimated_monthly_savings(self) -> float:
        return round(
            sum(f.monthly_cost for f in self.findings if f.monthly_cost is not None), 2
        )

    @property
    def covered_resources(self) -> int:
        """Resources at least one rule was able to evaluate."""
        return self.resources_scanned - len(self.uncovered)

    @property
    def fully_covered(self) -> bool:
        """True when every scanned resource had at least one applicable rule."""
        return not self.uncovered

    @property
    def uncovered_by_provider(self) -> dict[str, int]:
        from cairn.providers import provider_for
        counts: Counter[str] = Counter()
        for address in self.uncovered:
            rtype = address.rsplit(".", 1)[0]
            counts[provider_for(rtype)] += 1
        return dict(counts)


def reconcile(findings: list[Finding]) -> list[TradeOff]:
    """Detect resources where disciplines collide and describe the trade-off."""
    by_address: dict[str, set[Category]] = {}
    for finding in findings:
        by_address.setdefault(finding.address, set()).add(finding.category)

    trade_offs: list[TradeOff] = []
    for address in sorted(by_address):
        categories = by_address[address]
        if Category.COST in categories and Category.SECURITY in categories:
            trade_offs.append(
                TradeOff(
                    address=address,
                    categories=tuple(sorted(c.value for c in categories)),
                    note=(
                        "Cost and security findings touch this resource. "
                        "Sequence the security fix first, then right-size — "
                        "resizing an exposed resource first just makes the "
                        "breach cheaper to run."
                    ),
                )
            )
        elif Category.COST in categories and Category.RELIABILITY in categories:
            trade_offs.append(
                TradeOff(
                    address=address,
                    categories=tuple(sorted(c.value for c in categories)),
                    note=(
                        "Cost and reliability findings touch this resource. "
                        "Confirm the resilience fix (backups/versioning) is "
                        "in place before shrinking capacity."
                    ),
                )
            )
    return trade_offs


def _with_blast_radius(finding: Finding, graph: ResourceGraph) -> Finding:
    dependents = graph.dependents_of(finding.address)
    if not dependents:
        return finding
    return replace(finding, blast_radius=tuple(dependents))


def _apply_suppressions(
    findings: list[Finding], suppressions: list[Suppression]
) -> tuple[list[Finding], list[SuppressedFinding]]:
    kept: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        marker = next(
            (s for s in suppressions
             if s.matches(finding.rule_id, finding.address, finding.file)),
            None,
        )
        if marker is None:
            kept.append(finding)
        else:
            suppressed.append(
                SuppressedFinding(finding=finding, reason=marker.reason,
                                  marker_line=marker.line)
            )
    return kept, suppressed


def run_scan(
    target: Path,
    config: Config,
    *,
    use_plugins: bool = True,
    providers: tuple[str, ...] | None = None,
) -> ScanResult:
    """Execute a full read-only scan of *target* under *config*.

    *providers*, when given, keeps only findings whose provider is in the
    set — the cloud-agnostic filter (``--provider aws,azure``).
    """
    started = time.perf_counter()
    plugin_warnings = load_plugins() if use_plugins else []
    parsed = parse_path(target)
    manifests = kubernetes.parse_path(target)
    parsed.resources.extend(manifests.resources)
    parsed.errors.extend(manifests.errors)
    parsed.files_scanned += manifests.files_scanned
    ctx = ScanContext(
        resources=tuple(parsed.resources),
        required_tags=config.required_tags,
    )

    raw: list[Finding] = []
    rules = all_rules()
    for resource in parsed.resources:
        for rule in rules:
            if rule.applies_to(resource):
                raw.extend(rule.run(resource, ctx))
    # Coverage is measured at the *provider* level: a resource is "uncovered"
    # only when Cairn ships no rule pack for its provider at all (e.g.
    # Oracle Cloud, DigitalOcean). Companion resources within a supported
    # provider (an aws_s3_bucket_versioning next to an aws_s3_bucket) are
    # considered covered — the provider is scanned even if that specific
    # type has no dedicated rule. This is what makes a "not scanned" notice
    # signal a genuine gap (an unsupported provider) rather than plumbing.
    uncovered = sorted(
        r.address for r in parsed.resources if not is_covered(r.type)
    )
    uncovered_types = sorted({addr.rsplit(".", 1)[0] for addr in uncovered})

    graph = build_graph(tuple(parsed.resources))
    applied = config.apply(raw)
    if providers:
        wanted = {p.lower() for p in providers}
        applied = [f for f in applied if f.provider in wanted]
    enriched = [_with_blast_radius(f, graph) for f in applied]
    findings, suppressed = _apply_suppressions(
        sort_findings(enriched), parsed.suppressions
    )
    return ScanResult(
        graph=graph,
        target=str(target),
        findings=findings,
        suppressed=suppressed,
        warnings=list(parsed.warnings) + plugin_warnings,
        trade_offs=reconcile(findings),
        parse_errors=parsed.errors,
        files_scanned=parsed.files_scanned,
        resources_scanned=len(parsed.resources),
        duration_seconds=time.perf_counter() - started,
        uncovered=uncovered,
        uncovered_types=uncovered_types,
    )
