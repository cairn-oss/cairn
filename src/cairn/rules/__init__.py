"""Rule packages. Importing this package registers every built-in rule."""

from cairn.rules import (  # noqa: F401
    azure,
    cost,
    gcp,
    governance,
    kubernetes,
    reliability,
    security,
    vsphere,
)
from cairn.rules.base import Detection, Rule, all_rules, get_rule, load_plugins, rule

__all__ = ["Detection", "Rule", "all_rules", "get_rule", "load_plugins", "rule"]


def coverage_summary() -> dict[str, int]:
    """Rule count per provider, for `cairn providers`."""
    from collections import Counter

    from cairn.providers import provider_for

    counts: Counter[str] = Counter()
    for registered in all_rules():
        if registered.resource_types:
            for prov in {provider_for(rt) for rt in registered.resource_types}:
                counts[prov] += 1
        else:
            counts["(any)"] += 1
    return dict(counts)
