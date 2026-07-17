"""Guarded autonomy — Trust Ladder rung 2 (``cairn fix --apply``).

This is the first time Cairn *writes* to a user's files, so it is
deliberately the narrowest possible capability:

* Only a **hard-coded whitelist** of fix classes is eligible — changes
  whose Terraform plan diff is attribute-only and non-destructive (add a
  tag, flip gp2→gp3, set deletion_protection/IMDSv2). The whitelist lives
  in code and a scanned repo cannot extend it.
* Every class is **per-category opt-in** via policy (``autonomy.allow``).
  Nothing not explicitly granted is ever applied; the default is to apply
  nothing.
* Applying refuses to run on a **dirty git worktree** (or outside git),
  so every change is reviewable as a clean diff and trivially revertible.
* ``--dry-run`` is the default; writing requires an explicit ``--apply``.
* Every applied change is **audited** with before/after content hashes.

The mechanism edits the specific attribute line in place, preserving the
rest of the file. If the expected text isn't found exactly, the fix is
skipped (reported), never guessed — a wrong edit to infrastructure code is
worse than no edit.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from cairn.engine import ScanResult
from cairn.findings import Finding

#: Eligible fix classes: rule_id -> (attribute regex to find, replacement).
#: Each is an attribute-only, non-destructive change with a stable pattern.
_ELIGIBLE: dict[str, tuple[str, str]] = {
    "COST002": (r'type\s*=\s*"gp2"', 'type = "gp3"'),                       # gp2 -> gp3
    "SEC005": (r'storage_encrypted\s*=\s*false', "storage_encrypted = true"),
    "SEC006": (r'encrypted\s*=\s*false', "encrypted = true"),
    "REL003": (
        r'deletion_protection\s*=\s*false',
        "deletion_protection = true",
    ),
}

#: Which autonomy category each eligible rule belongs to (the policy grant).
_CATEGORY: dict[str, str] = {
    "COST002": "volume-types",
    "SEC005": "encryption",
    "SEC006": "encryption",
    "REL003": "deletion-protection",
}


class AutofixError(Exception):
    """Applying is unsafe to proceed (e.g. dirty or non-git worktree)."""


@dataclass
class Applied:
    rule_id: str
    address: str
    file: str
    before_sha: str
    after_sha: str


@dataclass
class FixPlan:
    eligible: list[Finding] = field(default_factory=list)
    applied: list[Applied] = field(default_factory=list)
    skipped: list[tuple[Finding, str]] = field(default_factory=list)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _git_clean(root: Path) -> bool:
    try:
        result = subprocess.run(  # noqa: S603 - fixed args, no shell
            ["git", "-C", str(root), "status", "--porcelain"],  # noqa: S607
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == ""


def _atomic_write(path: Path, text: str) -> None:
    """Write *text* to *path* atomically, preserving the file's mode.

    Writes to a temp file in the same directory, flushes to disk, then
    ``os.replace`` (an atomic rename on the same filesystem). A crash mid-write
    can therefore never leave a truncated IaC file — the original stays intact
    until the fully-written replacement swaps in.
    """
    try:
        mode = path.stat().st_mode
    except OSError:
        mode = 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cairn-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def eligible_findings(result: ScanResult, allowed_categories: tuple[str, ...]) -> list[Finding]:
    """Findings whose fix class is both whitelisted and policy-granted."""
    granted = set(allowed_categories)
    return [
        f
        for f in result.findings
        if f.rule_id in _ELIGIBLE and _CATEGORY.get(f.rule_id) in granted
    ]


def plan_fixes(
    result: ScanResult,
    allowed_categories: tuple[str, ...],
    *,
    apply: bool,
    root: Path,
) -> FixPlan:
    """Compute (and optionally apply) the eligible, granted fixes.

    Raises :class:`AutofixError` if *apply* is requested on a worktree that
    is not a clean git checkout — the safety precondition for autonomy.
    """
    plan = FixPlan(eligible=eligible_findings(result, allowed_categories))

    if apply and not _git_clean(root):
        raise AutofixError(
            "refusing to apply: the target is not a clean git worktree. "
            "Autonomy requires a clean checkout so every change is a "
            "reviewable, revertible diff. Commit or stash first."
        )

    for finding in plan.eligible:
        pattern, replacement = _ELIGIBLE[finding.rule_id]
        path = Path(finding.file)
        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            plan.skipped.append((finding, f"cannot read file: {exc}"))
            continue

        new_text, count = re.subn(pattern, replacement, original, count=1)
        if count == 0:
            plan.skipped.append(
                (finding, "expected attribute text not found exactly; skipped (never guessed)")
            )
            continue

        if apply:
            try:
                _atomic_write(path, new_text)
            except OSError as exc:
                plan.skipped.append((finding, f"cannot write file: {exc}"))
                continue

        plan.applied.append(
            Applied(
                rule_id=finding.rule_id,
                address=finding.address,
                file=finding.file,
                before_sha=_sha(original),
                after_sha=_sha(new_text),
            )
        )
    return plan


def render_plan(plan: FixPlan, *, applied: bool) -> str:
    """Render an autofix plan as text (dry-run preview or applied summary)."""
    verb = "Applied" if applied else "Would apply"
    lines = [f"Cairn autofix ({'apply' if applied else 'dry-run'}):", ""]
    if not plan.eligible:
        lines.append("  no eligible, policy-granted fixes for this scan.")
        lines.append("")
        lines.append("Grant fix classes with autonomy.allow in .cairn.yaml; "
                     "only a fixed whitelist of non-destructive changes is eligible.")
        return "\n".join(lines)
    for a in plan.applied:
        lines.append(f"  {verb}: {a.rule_id} on {a.address}  ({a.file})  "
                     f"{a.before_sha} -> {a.after_sha}")
    for finding, reason in plan.skipped:
        lines.append(f"  skipped: {finding.rule_id} on {finding.address} — {reason}")
    lines.append("")
    if applied:
        lines.append("Changes written. Review the git diff and commit; "
                     "revert with your VCS if needed. Each change is audited.")
    else:
        lines.append("Dry run — nothing changed. Re-run with --apply on a clean "
                     "git worktree to write these fixes.")
    return "\n".join(lines)
