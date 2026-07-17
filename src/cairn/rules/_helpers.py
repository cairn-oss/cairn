"""Small shared helpers for rule authors."""

from __future__ import annotations

from typing import Any

from cairn.rules.base import ScanContext
from cairn.terraform import Resource


def blocks(body: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return nested block(s) under *key* as a list of dicts.

    HCL repeated blocks parse to a list; a single block may parse to a
    dict. Attributes that aren't blocks are ignored.
    """
    value = body.get(key)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def is_interpolation(value: Any) -> bool:
    """True when *value* is a Terraform expression rather than a literal."""
    return isinstance(value, str) and "${" in value


def references_resource(value: Any, address: str) -> bool:
    """True when attribute *value* references the given resource address."""
    return isinstance(value, str) and address in value


def has_companion(ctx: ScanContext, companion_type: str, attr: str, target: Resource) -> bool:
    """True when a companion resource (e.g. ``aws_s3_bucket_versioning``)
    exists whose *attr* references *target*.

    Terraform v4+ AWS provider split many bucket settings into standalone
    resources; checking for them avoids false positives.
    """
    for companion in ctx.by_type(companion_type):
        value = companion.body.get(attr)
        if references_resource(value, target.address) or value == target.name:
            return True
    return False


def port_range_includes(entry: dict[str, Any], port: int) -> bool:
    """True when an ingress/egress block's port range covers *port*."""
    try:
        low = int(entry.get("from_port", -1))
        high = int(entry.get("to_port", -1))
    except (TypeError, ValueError):
        return False
    if low == 0 and high == 0:  # all ports shorthand
        return True
    return low <= port <= high
