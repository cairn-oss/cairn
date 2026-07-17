"""Drift detection — declared IaC vs. actual cloud state (read-only).

Cairn never touches cloud credentials. Instead the *user* produces a
state snapshot with a command they already trust —
``terraform show -json > state.json`` — and Cairn compares the declared
configuration against it locally. This keeps the local-first, no-standing-
access posture intact while still answering "does reality match the code?".

Classification per resource address:

* ``in_sync``  — declared and present in state
* ``missing``  — declared in code but absent from state (never applied, or
                 destroyed out of band)
* ``unmanaged``— present in state but not in the scanned code (drifted in,
                 or managed elsewhere)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cairn.terraform import parse_path


class DriftError(Exception):
    """The state snapshot could not be read or parsed."""


@dataclass
class DriftReport:
    in_sync: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unmanaged: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.missing or self.unmanaged)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "in_sync": self.in_sync,
            "missing": self.missing,
            "unmanaged": self.unmanaged,
        }


def _state_addresses(state: dict[str, Any]) -> set[str]:
    """Extract resource addresses from a `terraform show -json` document.

    Handles both the planned-values shape and the state values shape by
    walking root and child modules for ``resources[].address``.
    """
    addresses: set[str] = set()

    def walk_module(module: dict[str, Any]) -> None:
        for resource in module.get("resources", []) or []:
            address = resource.get("address")
            if isinstance(address, str):
                # strip module prefixes for comparison with flat code addresses
                addresses.add(address.split(".")[-2] + "." + address.split(".")[-1]
                              if address.count(".") >= 3 else address)
            elif isinstance(resource.get("type"), str) and isinstance(resource.get("name"), str):
                addresses.add(f"{resource['type']}.{resource['name']}")
        for child in module.get("child_modules", []) or []:
            walk_module(child)

    values = state.get("values", state)
    root = values.get("root_module") if isinstance(values, dict) else None
    if isinstance(root, dict):
        walk_module(root)
    return addresses


def detect_drift(code_path: Path, state_path: Path) -> DriftReport:
    """Compare declared resources under *code_path* to a state snapshot."""
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DriftError(f"could not read state snapshot {state_path}: {exc}") from exc
    if not isinstance(state, dict):
        raise DriftError("state snapshot must be a JSON object from `terraform show -json`")

    declared = {r.address for r in parse_path(code_path).resources}
    in_state = _state_addresses(state)

    report = DriftReport(
        in_sync=sorted(declared & in_state),
        missing=sorted(declared - in_state),
        unmanaged=sorted(in_state - declared),
    )
    return report


def render_drift(report: DriftReport) -> str:
    """Render a drift report as text (in-sync / missing / unmanaged)."""
    lines = ["Cairn drift report (declared IaC vs. state snapshot):", ""]
    lines.append(f"  in sync:   {len(report.in_sync)}")
    for address in report.missing:
        lines.append(f"  - MISSING   {address}  (declared but not in state)")
    for address in report.unmanaged:
        lines.append(f"  + UNMANAGED {address}  (in state but not declared)")
    if not report.has_drift:
        lines.append("  no drift: every declared resource is present in state.")
    lines.append("")
    lines.append("State snapshot supplied by you; Cairn reads no cloud credentials.")
    return "\n".join(lines)
