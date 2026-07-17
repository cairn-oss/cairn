"""Inline `# cairn:ignore` markers: suppress with a reason, loudly warn without."""

from pathlib import Path

from cairn.engine import run_scan
from cairn.policy import Config

from .conftest import EXAMPLES

SUPPRESSED_SG = """
resource "aws_security_group" "bastion" {
  ingress {
    # cairn:ignore SEC001 reason=reachable only via VPN
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "b" }
}
"""


def _scan(tmp_path: Path, source: str):
    (tmp_path / "main.tf").write_text(source)
    return run_scan(tmp_path, Config())


def test_marker_with_reason_suppresses(tmp_path: Path):
    result = _scan(tmp_path, SUPPRESSED_SG)
    assert [f.rule_id for f in result.findings] == []
    assert len(result.suppressed) == 1
    assert result.suppressed[0].finding.rule_id == "SEC001"
    assert result.suppressed[0].reason == "reachable only via VPN"
    assert result.warnings == []


def test_marker_without_reason_warns_and_does_not_suppress(tmp_path: Path):
    result = _scan(tmp_path, SUPPRESSED_SG.replace(" reason=reachable only via VPN", ""))
    assert any(f.rule_id == "SEC001" for f in result.findings)
    assert result.suppressed == []
    assert any("no reason=" in w for w in result.warnings)


def test_marker_outside_any_resource_warns(tmp_path: Path):
    result = _scan(tmp_path, "# cairn:ignore SEC001 reason=lost\n" + SUPPRESSED_SG)
    assert any("outside any resource" in w for w in result.warnings)


def test_marker_only_covers_its_own_resource(tmp_path: Path):
    two = SUPPRESSED_SG + """
resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "o" }
}
"""
    result = _scan(tmp_path, two)
    assert [f.address for f in result.findings if f.rule_id == "SEC001"] == [
        "aws_security_group.open"
    ]


def test_suppressed_example_is_clean_and_documented():
    result = run_scan(EXAMPLES / "suppressed", Config())
    assert result.findings == []
    assert len(result.suppressed) == 1
    assert "VPN" in result.suppressed[0].reason
