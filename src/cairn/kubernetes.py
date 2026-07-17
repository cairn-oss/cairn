"""Kubernetes manifest discovery and parsing.

Manifests flow into the same :class:`~cairn.terraform.Resource` model
as Terraform (``type`` becomes ``k8s_<kind>``), so rules, policy,
reconciliation and every reporter work unchanged — the unified findings
model absorbs a whole new IaC target without touching the pipeline.

Safety posture mirrors the Terraform parser: no symlink traversal, per-file
error containment, and size/anchor ceilings because scanned repositories
are untrusted input (YAML anchor expansion is a classic memory bomb).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from cairn.terraform import ParseError, ParseResult, Resource

#: Directories whose YAML is never a deployable manifest.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".github", ".terraform",
    "node_modules", "__pycache__", "vendor",
}

#: Per-file ceilings for untrusted YAML.
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ANCHORS = 200


def discover_files(path: Path) -> list[Path]:
    """Every ``.yaml``/``.yml`` under *path*; symlinked dirs never followed."""
    if path.is_file():
        return [path] if path.suffix in (".yaml", ".yml") else []
    files: list[Path] = []
    for root, dirs, names in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        files.extend(
            Path(root) / n
            for n in names
            if n.endswith((".yaml", ".yml")) and not n.startswith(".")
        )
    return sorted(files)


def _is_manifest(doc: object) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("kind"), str) and "apiVersion" in doc


def parse_file(path: Path) -> tuple[list[Resource], ParseError | None]:
    """Extract manifests from one YAML file; non-manifest YAML is ignored.

    A repository is full of YAML that is not Kubernetes (CI configs, lock
    files, Cairn's own policy). Requiring ``apiVersion`` + ``kind``
    keeps false positives out without a filename convention.
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], ParseError(
                file=str(path),
                message=f"file larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB; skipped",
            )
        source = path.read_text(encoding="utf-8", errors="replace")
        if source.count("&") > MAX_ANCHORS:
            return [], ParseError(
                file=str(path),
                message=f"more than {MAX_ANCHORS} YAML anchors; skipped (expansion-bomb guard)",
            )
        documents = list(yaml.safe_load_all(source))
    except Exception as exc:  # yaml raises many types; contain them all
        return [], ParseError(file=str(path), message=str(exc).splitlines()[0][:300])

    resources = []
    for doc in documents:
        if not _is_manifest(doc):
            continue
        metadata = doc.get("metadata") or {}
        name = metadata.get("name") if isinstance(metadata, dict) else None
        resources.append(
            Resource(
                type=f"k8s_{str(doc['kind']).lower()}",
                name=str(name) if name else "unnamed",
                body=doc,
                file=str(path),
                line=0,  # PyYAML safe_load drops positions; SARIF clamps to 1
            )
        )
    return resources, None


def parse_path(path: Path) -> ParseResult:
    """Discover and parse all Kubernetes manifests under *path*."""
    result = ParseResult()
    for file in discover_files(path):
        resources, error = parse_file(file)
        result.files_scanned += 1
        result.resources.extend(resources)
        if error is not None:
            result.errors.append(error)
    return result
