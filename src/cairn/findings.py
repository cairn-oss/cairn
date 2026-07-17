"""The unified findings model.

Every detector in every discipline emits the same schema so that cost,
security, reliability and governance findings can be ranked, filtered and
*reconciled* in a single view. This module is the contract between rules,
the engine, the policy layer and every reporter.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Finding severity, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """0 is most severe; useful as a sort key."""
        return _SEVERITY_ORDER.index(self)

    def at_least(self, other: Severity) -> bool:
        """True if this severity is as severe as, or more severe than, *other*."""
        return self.rank <= other.rank

    @classmethod
    def from_str(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None


_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Category(enum.Enum):
    """The discipline a finding belongs to."""

    SECURITY = "SECURITY"
    COST = "COST"
    RELIABILITY = "RELIABILITY"
    GOVERNANCE = "GOVERNANCE"


@dataclass(frozen=True)
class Finding:
    """A single, actionable issue discovered in the scanned configuration.

    Attributes:
        rule_id: Stable identifier of the rule that produced the finding
            (e.g. ``SEC001``). Never reused across rule versions.
        severity: How urgent the finding is.
        category: Which discipline the finding belongs to.
        resource_type: Terraform resource type (e.g. ``aws_s3_bucket``).
        resource_name: Terraform resource name label.
        file: Path of the file the resource was declared in.
        line: 1-based line the resource block starts on (0 if unknown).
        message: Plain-English statement of the problem.
        fix: Plain-English remediation guidance.
        fix_code: Optional ready-to-apply HCL snippet.
        monthly_cost: Estimated monthly waste in USD for cost findings
            (positive = money saved by fixing), ``None`` where not applicable.
        references: Documentation / benchmark URLs backing the rule.
    """

    rule_id: str
    severity: Severity
    category: Category
    resource_type: str
    resource_name: str
    file: str
    line: int
    message: str
    fix: str
    fix_code: str | None = None
    monthly_cost: float | None = None
    references: tuple[str, ...] = field(default_factory=tuple)
    blast_radius: tuple[str, ...] = field(default_factory=tuple)
    provider: str = "other"

    @property
    def address(self) -> str:
        """Terraform-style resource address, e.g. ``aws_s3_bucket.logs``."""
        return f"{self.resource_type}.{self.resource_name}"

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable representation used by machine reporters."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category.value,
            "resource": self.address,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "fix": self.fix,
            "fix_code": self.fix_code,
            "monthly_cost_usd": self.monthly_cost,
            "references": list(self.references),
            "blast_radius": list(self.blast_radius),
            "provider": self.provider,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic ordering: severity, then file, then line, then rule id."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.file, f.line, f.rule_id, f.address))
