"""Rule framework: how detectors are written and registered.

A rule is a plain function decorated with :func:`rule`. It receives one
:class:`~cairn.terraform.Resource` plus a :class:`ScanContext` (the full
set of resources, for cross-resource analysis) and yields
:class:`Detection` objects. The engine combines rule metadata with each
detection to produce the unified :class:`~cairn.findings.Finding`.

This is deliberately the smallest possible authoring surface — adding a
community rule is "write one function, decorate it, done".
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace

from cairn.findings import Category, Finding, Severity
from cairn.providers import provider_for
from cairn.terraform import Resource

CheckFn = Callable[[Resource, "ScanContext"], Iterable["Detection"]]


@dataclass(frozen=True)
class Detection:
    """What a rule reports for one resource; metadata comes from the rule."""

    message: str
    fix: str
    fix_code: str | None = None
    severity: Severity | None = None  # override the rule default when set
    monthly_cost: float | None = None


@dataclass(frozen=True)
class ScanContext:
    """Shared, read-only view of the whole scan for cross-resource rules.

    Also carries the slice of policy configuration rules may consult
    (e.g. organization-required tags).
    """

    resources: tuple[Resource, ...] = ()
    required_tags: tuple[str, ...] = ()

    def by_type(self, rtype: str) -> list[Resource]:
        return [r for r in self.resources if r.type == rtype]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: Category
    severity: Severity
    description: str
    check: CheckFn
    resource_types: tuple[str, ...] | None = None  # None = every resource
    references: tuple[str, ...] = field(default_factory=tuple)
    source: str = "builtin"  # "builtin" or the plugin package that registered it

    def applies_to(self, resource: Resource) -> bool:
        return self.resource_types is None or resource.type in self.resource_types

    def run(self, resource: Resource, ctx: ScanContext) -> Iterator[Finding]:
        for detection in self.check(resource, ctx):
            yield Finding(
                rule_id=self.id,
                severity=detection.severity or self.severity,
                category=self.category,
                resource_type=resource.type,
                resource_name=resource.name,
                file=resource.file,
                line=resource.line,
                message=detection.message,
                fix=detection.fix,
                fix_code=detection.fix_code,
                monthly_cost=detection.monthly_cost,
                references=self.references,
                provider=provider_for(resource.type),
            )


_REGISTRY: dict[str, Rule] = {}


def rule(
    *,
    id: str,
    title: str,
    category: Category,
    severity: Severity,
    description: str,
    resource_types: tuple[str, ...] | None = None,
    references: tuple[str, ...] = (),
) -> Callable[[CheckFn], CheckFn]:
    """Register a detector function as a Cairn rule."""

    def decorator(fn: CheckFn) -> CheckFn:
        if id in _REGISTRY:
            raise ValueError(f"duplicate rule id: {id}")
        _REGISTRY[id] = Rule(
            id=id,
            title=title,
            category=category,
            severity=severity,
            description=description,
            check=fn,
            resource_types=resource_types,
            references=references,
        )
        return fn

    return decorator


def all_rules() -> list[Rule]:
    """Every registered rule, ordered by id (deterministic)."""
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def get_rule(rule_id: str) -> Rule | None:
    return _REGISTRY.get(rule_id)


_PLUGINS_LOADED = False


def load_plugins() -> list[str]:
    """Discover and import third-party rule packages via entry points.

    Any installed distribution advertising the ``cairn.rules`` entry-point
    group is imported, which runs its ``@rule`` registrations. Provenance is
    stamped onto each rule the plugin adds so ``cairn rules`` can show
    where a rule came from and CI can pin to builtins only.

    Loading is best-effort and idempotent: a broken plugin is skipped with a
    recorded warning, never crashing the scan. Returns the list of warnings.
    """
    global _PLUGINS_LOADED
    warnings: list[str] = []
    if _PLUGINS_LOADED:
        return warnings
    _PLUGINS_LOADED = True

    from importlib import metadata

    try:
        entry_points = metadata.entry_points(group="cairn.rules")
    except Exception:  # metadata backends vary; absence must never break a scan
        return warnings

    for entry_point in entry_points:
        before = set(_REGISTRY)
        try:
            entry_point.load()
        except Exception as exc:  # a broken plugin must not break Cairn
            warnings.append(f"failed to load rule plugin {entry_point.name!r}: {exc}")
            continue
        package = entry_point.value.split(":")[0].split(".")[0]
        for rule_id in set(_REGISTRY) - before:
            existing = _REGISTRY[rule_id]
            _REGISTRY[rule_id] = replace(existing, source=package)
    return warnings
