"""Terraform (HCL2) discovery, parsing and normalization.

Design notes:
    * ``python-hcl2`` keeps the surrounding quotes on string literals,
      represents heredocs as ``"<<EOF\\n...\\nEOF"`` and injects
      ``__is_block__`` markers; :func:`_clean` normalizes all of this so
      rules can work with plain Python values.
    * The parser does not expose source positions, so resource start lines
      are recovered with a tolerant regex pass over the raw source. Line
      numbers therefore degrade gracefully to ``0`` rather than failing.
    * Parsing is *best-effort per file*: one malformed file must never abort
      a repository scan. Errors are collected and reported, not raised.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2

#: Directories never worth scanning (vendored modules, VCS internals, ...).
SKIP_DIRS = {".terraform", ".git", ".hg", ".svn", "node_modules", "__pycache__"}

#: Per-file parse ceiling; anything larger is reported and skipped.
MAX_FILE_BYTES = 10 * 1024 * 1024

_RESOURCE_HEADER = re.compile(
    r'^[ \t]*resource[ \t]+"(?P<type>[\w-]+)"[ \t]+"(?P<name>[\w.-]+)"[ \t]*\{',
    re.MULTILINE,
)

_HEREDOC = re.compile(r"^<<-?(?P<delim>\w+)\n(?P<body>.*)\n[ \t]*(?P=delim)$", re.DOTALL)

_SUPPRESSION = re.compile(
    r"#\s*cairn:ignore\s+(?P<rule>[A-Z][A-Z0-9]*)(?:\s+reason=(?P<reason>\S.*?))?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Resource:
    """A single Terraform resource block, normalized for rule consumption."""

    type: str
    name: str
    body: dict[str, Any]
    file: str
    line: int = 0

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def tags(self) -> dict[str, Any]:
        tags = self.body.get("tags")
        return tags if isinstance(tags, dict) else {}


@dataclass(frozen=True)
class Suppression:
    """An inline ``# cairn:ignore RULE reason=...`` marker.

    Reasons are mandatory by design: an exception without a recorded
    rationale is indistinguishable from an accident, both to reviewers
    and to the future owner of the file.
    """

    file: str
    line: int
    rule_id: str
    reason: str
    address: str

    def matches(self, rule_id: str, address: str, file: str) -> bool:
        return self.rule_id == rule_id and self.address == address and self.file == file


@dataclass(frozen=True)
class ParseError:
    """A file Cairn could not parse (reported, never fatal)."""

    file: str
    message: str


@dataclass
class ParseResult:
    resources: list[Resource] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0


@dataclass(frozen=True)
class FileParse:
    """Everything extracted from a single file."""

    resources: tuple[Resource, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    warnings: tuple[str, ...] = ()
    error: ParseError | None = None


def _unquote(value: Any) -> Any:
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    if isinstance(value, str):
        # hcl2 represents heredocs as "<<EOF\n...\nEOF"; expose only the body
        # so JSON policy documents can be parsed by rules.
        heredoc = _HEREDOC.match(value)
        if heredoc:
            return heredoc.group("body")
    return value


def _clean(obj: Any) -> Any:
    """Strip parser artifacts (quoted strings, heredoc markers, __is_block__)."""
    if isinstance(obj, dict):
        return {
            _unquote(k): _clean(v)
            for k, v in obj.items()
            if not (isinstance(k, str) and k.startswith("__"))
        }
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    return _unquote(obj)


def discover_files(path: Path) -> list[Path]:
    """Return every ``.tf`` file under *path* (or *path* itself if a file).

    Directory symlinks are never followed: a scanned repository must not be
    able to route the scan outside itself (or into a cycle).
    """
    if path.is_file():
        # A directly-passed non-.tf file belongs to another parser
        # (e.g. Kubernetes YAML); claiming it here would double-count it
        # and report a spurious HCL parse error.
        return [path] if path.suffix == ".tf" else []
    files: list[Path] = []
    for root, dirs, names in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        files.extend(Path(root) / n for n in names if n.endswith(".tf"))
    return sorted(files)


def _resource_lines(source: str) -> dict[tuple[str, str], int]:
    """Map ``(type, name)`` to the 1-based line its block starts on."""
    lines: dict[tuple[str, str], int] = {}
    for match in _RESOURCE_HEADER.finditer(source):
        line_no = source.count("\n", 0, match.start()) + 1
        lines.setdefault((match.group("type"), match.group("name")), line_no)
    return lines


def _extract_suppressions(
    source: str, file: str, starts: list[tuple[int, str]]
) -> tuple[list[Suppression], list[str]]:
    """Attach ``cairn:ignore`` markers to the resource block they sit in.

    A marker belongs to the most recent resource header at or above it.
    Markers without a reason, or outside any resource, do not suppress —
    they surface as warnings instead, because a silent no-op marker would
    be worse than none at all.
    """
    suppressions: list[Suppression] = []
    warnings: list[str] = []
    for match in _SUPPRESSION.finditer(source):
        line_no = source.count("\n", 0, match.start()) + 1
        rule_id = match.group("rule")
        reason = (match.group("reason") or "").strip()
        owner = None
        for start, address in starts:
            if start <= line_no:
                owner = address
            else:
                break
        location = f"{file}:{line_no}"
        if owner is None:
            warnings.append(
                f"{location}: cairn:ignore marker is outside any resource block; ignored"
            )
            continue
        if not reason:
            warnings.append(
                f"{location}: cairn:ignore {rule_id} has no reason=...; "
                "a reason is required for the suppression to apply"
            )
            continue
        suppressions.append(
            Suppression(file=file, line=line_no, rule_id=rule_id, reason=reason, address=owner)
        )
    return suppressions, warnings


def parse_file(path: Path) -> FileParse:
    """Parse one Terraform file; never raises on bad input."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return FileParse(error=ParseError(
                file=str(path),
                message=f"file larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB; skipped",
            ))
        source = path.read_text(encoding="utf-8", errors="replace")
        data = _clean(hcl2.loads(source))
    except Exception as exc:  # lark raises many exception types; contain them all
        return FileParse(error=ParseError(file=str(path), message=str(exc).splitlines()[0][:300]))

    lines = _resource_lines(source)
    resources: list[Resource] = []
    for block in data.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for rtype, named in block.items():
            if not isinstance(named, dict):
                continue
            for name, body in named.items():
                if not isinstance(body, dict):
                    continue
                resources.append(
                    Resource(
                        type=str(rtype),
                        name=str(name),
                        body=body,
                        file=str(path),
                        line=lines.get((str(rtype), str(name)), 0),
                    )
                )
    starts = sorted((r.line, r.address) for r in resources if r.line)
    suppressions, warnings = _extract_suppressions(source, str(path), starts)
    return FileParse(
        resources=tuple(resources),
        suppressions=tuple(suppressions),
        warnings=tuple(warnings),
    )


def parse_path(path: Path) -> ParseResult:
    """Discover and parse all Terraform files under *path*."""
    result = ParseResult()
    for file in discover_files(path):
        parsed = parse_file(file)
        result.files_scanned += 1
        result.resources.extend(parsed.resources)
        result.suppressions.extend(parsed.suppressions)
        result.warnings.extend(parsed.warnings)
        if parsed.error is not None:
            result.errors.append(parsed.error)
    return result
