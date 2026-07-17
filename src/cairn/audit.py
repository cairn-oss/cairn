"""Audit trail — Trust Ladder rung 0.

Cairn's v0.1 posture is strictly read-only, but every scan is still
recorded to an append-only local JSONL log. This is deliberate: the audit
habit must exist *before* any autonomy (auto-PR, auto-remediation) is
introduced, so higher rungs inherit a working evidence trail.

The log stays on the user's machine (default ``~/.cairn/audit.jsonl``)
and contains only scan metadata — never file contents or findings bodies.
Failures to write are swallowed: auditing must never break a scan.
"""

from __future__ import annotations

import getpass
import json
import time
from pathlib import Path

from cairn import __version__
from cairn.policy import AuditConfig

TRUST_LEVEL = "read-only"  # rung 0 of the Trust Ladder


def default_path() -> Path:
    return Path.home() / ".cairn" / "audit.jsonl"


def record_scan(
    config: AuditConfig,
    *,
    target: str,
    files_scanned: int,
    resources_scanned: int,
    findings_by_severity: dict[str, int],
    duration_seconds: float,
    exit_code: int,
    action: str = "scan",
) -> None:
    if not config.enabled:
        return
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "cairn_version": __version__,
        "trust_level": TRUST_LEVEL,
        "action": action,
        "actor": _safe_user(),
        "target": target,
        "files_scanned": files_scanned,
        "resources_scanned": resources_scanned,
        "findings_by_severity": findings_by_severity,
        "duration_seconds": round(duration_seconds, 3),
        "exit_code": exit_code,
    }
    path = Path(config.path).expanduser() if config.path else default_path()
    if path.suffix != ".jsonl" or path.is_symlink():
        return  # never append to anything that isn't a plain .jsonl file
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass  # auditing is best-effort by design


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return "unknown"
