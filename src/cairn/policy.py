"""Policy-as-code: declarative org standards around the scan.

Configuration is loaded from ``.cairn.yaml`` (or ``--config``). It is
the deterministic guardrail layer of the architecture: rules detect,
policy decides what counts, what is ignored, and what fails CI.

Example::

    min_severity: LOW          # drop findings below this
    fail_on: HIGH              # exit 1 when findings at/above this remain
    required_tags: [Owner, CostCenter]
    disabled_rules: [GOV001]
    severity_overrides:
      COST002: MEDIUM
    ignores:
      - rule: SEC001
        resource: aws_security_group.legacy_*
        reason: grandfathered until Q3 migration
    llm:
      provider: none           # none | openai | anthropic | ollama
      model: gpt-4o-mini
    audit:
      enabled: true
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any

import yaml

from cairn.findings import Finding, Severity

CONFIG_FILENAMES = (".cairn.yaml", ".cairn.yml", "cairn.yaml")


class ConfigError(ValueError):
    """Raised when the policy file is malformed."""


@dataclass(frozen=True)
class Ignore:
    rule: str = "*"
    resource: str = "*"
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        return fnmatch.fnmatch(finding.rule_id, self.rule) and fnmatch.fnmatch(
            finding.address, self.resource
        )


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "none"  # none | openai | anthropic | ollama
    model: str = ""
    base_url: str = ""


@dataclass(frozen=True)
class BudgetConfig:
    """Cost guardrail consumed by ``cairn diff``."""

    max_monthly_increase: float | None = None


@dataclass(frozen=True)
class AutonomyConfig:
    """Trust Ladder rung 2 grants. Empty by default — nothing is applied
    unless a category is explicitly listed (a kill switch is `allow: []`)."""

    allow: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = True
    path: str = ""  # empty = ~/.cairn/audit.jsonl


@dataclass(frozen=True)
class Config:
    min_severity: Severity = Severity.INFO
    fail_on: Severity = Severity.HIGH
    fail_never: bool = False  # CLI --fail-on NEVER: report, always exit 0
    required_tags: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    ignores: tuple[Ignore, ...] = ()
    llm: LLMConfig = field(default_factory=LLMConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)
    source: str = "(defaults)"

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Apply overrides, ignores and the severity floor to raw findings."""
        result: list[Finding] = []
        for finding in findings:
            if finding.rule_id in self.disabled_rules:
                continue
            if any(ignore.matches(finding) for ignore in self.ignores):
                continue
            override = self.severity_overrides.get(finding.rule_id)
            if override is not None and override != finding.severity:
                finding = _with_severity(finding, override)
            if not finding.severity.at_least(self.min_severity):
                continue
            result.append(finding)
        return result

    def should_fail(self, findings: list[Finding]) -> bool:
        """CI gate: any finding at/above the fail_on threshold?"""
        if self.fail_never:
            return False
        return any(f.severity.at_least(self.fail_on) for f in findings)


def _with_severity(finding: Finding, severity: Severity) -> Finding:
    return Finding(
        rule_id=finding.rule_id,
        severity=severity,
        category=finding.category,
        resource_type=finding.resource_type,
        resource_name=finding.resource_name,
        file=finding.file,
        line=finding.line,
        message=finding.message,
        fix=finding.fix,
        fix_code=finding.fix_code,
        monthly_cost=finding.monthly_cost,
        references=finding.references,
    )


def _severity(value: Any, key: str) -> Severity:
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string severity")
    try:
        return Severity.from_str(value)
    except ValueError as exc:
        raise ConfigError(str(exc)) from None


def _parse(data: Any, source: str) -> Config:
    if data is None:
        return Config(source=source)
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: top level must be a mapping")

    known = {
        "min_severity", "fail_on", "required_tags", "disabled_rules",
        "severity_overrides", "ignores", "llm", "audit", "budget", "autonomy",
    }
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{source}: unknown key(s): {', '.join(sorted(unknown))}")

    kwargs: dict[str, Any] = {"source": source}
    if "min_severity" in data:
        kwargs["min_severity"] = _severity(data["min_severity"], "min_severity")
    if "fail_on" in data:
        kwargs["fail_on"] = _severity(data["fail_on"], "fail_on")
    if "required_tags" in data:
        kwargs["required_tags"] = tuple(str(t) for t in data["required_tags"] or [])
    if "disabled_rules" in data:
        kwargs["disabled_rules"] = tuple(str(r) for r in data["disabled_rules"] or [])
    if "severity_overrides" in data:
        overrides = data["severity_overrides"] or {}
        if not isinstance(overrides, dict):
            raise ConfigError(f"{source}: severity_overrides must be a mapping")
        kwargs["severity_overrides"] = {
            str(rule): _severity(sev, f"severity_overrides.{rule}")
            for rule, sev in overrides.items()
        }
    if "ignores" in data:
        entries = data["ignores"] or []
        if not isinstance(entries, list):
            raise ConfigError(f"{source}: ignores must be a list")
        kwargs["ignores"] = tuple(
            Ignore(
                rule=str(e.get("rule", "*")),
                resource=str(e.get("resource", "*")),
                reason=str(e.get("reason", "")),
            )
            for e in entries
            if isinstance(e, dict)
        )
    if "llm" in data and isinstance(data["llm"], dict):
        llm = data["llm"]
        kwargs["llm"] = LLMConfig(
            provider=str(llm.get("provider", "none")).lower(),
            model=str(llm.get("model", "")),
            base_url=str(llm.get("base_url", "")),
        )
    if "audit" in data and isinstance(data["audit"], dict):
        audit = data["audit"]
        audit_path = str(audit.get("path", ""))
        if audit_path and not audit_path.endswith(".jsonl"):
            # A discovered config could otherwise point the append-only log
            # at e.g. a shell rc file. Fail loudly, never silently comply.
            raise ConfigError(f"{source}: audit.path must end in .jsonl")
        kwargs["audit"] = AuditConfig(
            enabled=bool(audit.get("enabled", True)),
            path=audit_path,
        )
    if "autonomy" in data and isinstance(data["autonomy"], dict):
        allow = data["autonomy"].get("allow") or []
        if not isinstance(allow, list):
            raise ConfigError(f"{source}: autonomy.allow must be a list")
        kwargs["autonomy"] = AutonomyConfig(allow=tuple(str(a) for a in allow))
    if "budget" in data and isinstance(data["budget"], dict):
        raw_budget = data["budget"].get("max_monthly_increase")
        if raw_budget is not None:
            try:
                kwargs["budget"] = BudgetConfig(max_monthly_increase=float(raw_budget))
            except (TypeError, ValueError):
                raise ConfigError(
                    f"{source}: budget.max_monthly_increase must be a number"
                ) from None
    return Config(**kwargs)


_PACK_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _load_pack(reference: str, base_dir: Path, source: str) -> dict[str, Any]:
    """Resolve one ``extends:`` entry to raw config data.

    Bare names load bundled packs; anything else must be a relative
    ``.yaml`` path that stays inside the config file's directory. Absolute
    paths and ``..`` escapes are refused because a scanned repository's
    config must never read files outside itself. Packs cannot extend
    other packs — one level keeps merge order reviewable.
    """
    if _PACK_NAME.match(reference):
        pack_file = importlib_resources.files("cairn").joinpath("packs").joinpath(
            f"{reference}.yaml"
        )
        if not pack_file.is_file():
            raise ConfigError(
                f"{source}: unknown bundled pack '{reference}' "
                "(run 'cairn packs' guidance in docs/configuration.md)"
            )
        text = pack_file.read_text(encoding="utf-8")
    elif reference.endswith((".yaml", ".yml")):
        candidate = Path(reference)
        if candidate.is_absolute() or reference.startswith(("~", "/")):
            raise ConfigError(f"{source}: extends paths must be relative, got '{reference}'")
        resolved = (base_dir / candidate).resolve()
        if not resolved.is_relative_to(base_dir.resolve()):
            raise ConfigError(f"{source}: extends path escapes the config directory")
        if not resolved.is_file():
            raise ConfigError(f"{source}: pack file not found: {reference}")
        text = resolved.read_text(encoding="utf-8")
    else:
        raise ConfigError(
            f"{source}: extends entries are bundled pack names or relative "
            f".yaml paths, got '{reference}'"
        )
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: pack '{reference}' is invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: pack '{reference}' must be a mapping")
    if "extends" in data:
        raise ConfigError(f"{source}: pack '{reference}' may not itself use extends")
    return data


def _merge_config_data(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Overlay wins on scalars; lists union; mappings merge shallowly."""
    merged = dict(base)
    for key, value in overlay.items():
        if key in ("required_tags", "disabled_rules") and key in merged:
            existing = list(merged[key] or [])
            seen = existing + [v for v in (value or []) if v not in existing]
            merged[key] = seen
        elif key == "ignores" and key in merged:
            merged[key] = list(merged[key] or []) + list(value or [])
        elif key in ("severity_overrides", "llm", "audit", "budget") and isinstance(
            merged.get(key), dict
        ) and isinstance(value, dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def load_config(explicit: Path | None = None, search_dir: Path | None = None) -> Config:
    """Load policy config from *explicit* path or discover it in *search_dir*.

    Returns defaults when no file exists. Raises :class:`ConfigError` on a
    malformed file (a broken policy must fail loudly, not silently pass).
    """
    path: Path | None = explicit
    if path is None and search_dir is not None:
        base = search_dir if search_dir.is_dir() else search_dir.parent
        for name in CONFIG_FILENAMES:
            candidate = base / name
            if candidate.is_file():
                path = candidate
                break
    if path is None:
        return Config()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if isinstance(data, dict) and "extends" in data:
        references = data.pop("extends")
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            raise ConfigError(f"{path}: extends must be a name or a list")
        merged: dict[str, Any] = {}
        for reference in references:
            merged = _merge_config_data(merged, _load_pack(str(reference), path.parent, str(path)))
        data = _merge_config_data(merged, data)
    return _parse(data, str(path))
