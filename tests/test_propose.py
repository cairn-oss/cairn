"""`cairn propose` — the rung-1 artifact: drafts changes, modifies nothing."""

import hashlib
from pathlib import Path

from cairn.cli import EXIT_OK, main
from cairn.engine import run_scan
from cairn.policy import Config
from cairn.report.proposal import render_proposal

from .conftest import EXAMPLES


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def test_proposal_contains_patches_and_sequencing():
    result = run_scan(EXAMPLES / "vulnerable", Config())
    out = render_proposal(result)
    assert out.startswith("# Cairn remediation proposal")
    assert "```hcl" in out
    assert "publicly_accessible = false" in out
    assert "## Sequencing" in out


def test_clean_scan_proposes_nothing():
    result = run_scan(EXAMPLES / "clean", Config())
    assert "Nothing to propose" in render_proposal(result)


def test_cli_propose_writes_file_and_modifies_nothing(tmp_path, capsys):
    before = _tree_digest(EXAMPLES / "vulnerable")
    config = tmp_path / "cfg.yaml"
    config.write_text("audit:\n  enabled: false\n")
    out_file = tmp_path / "proposal.md"
    code = main(
        ["propose", str(EXAMPLES / "vulnerable"), "--config", str(config),
         "--output", str(out_file)]
    )
    assert code == EXIT_OK
    assert "remediation proposal" in out_file.read_text()
    assert _tree_digest(EXAMPLES / "vulnerable") == before
