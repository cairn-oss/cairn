"""Drift detection against a terraform show -json snapshot (read-only)."""

import json
from pathlib import Path

import pytest

from cairn.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from cairn.drift import DriftError, detect_drift


def _code(tmp_path: Path, *addresses: str) -> Path:
    body = "\n".join(
        f'resource "{a.split(".")[0]}" "{a.split(".")[1]}" {{}}' for a in addresses
    )
    (tmp_path / "main.tf").write_text(body + "\n")
    return tmp_path


def _state(tmp_path: Path, *addresses: str) -> Path:
    doc = {
        "values": {
            "root_module": {
                "resources": [
                    {"address": a, "type": a.split(".")[0], "name": a.split(".")[1]}
                    for a in addresses
                ]
            }
        }
    }
    path = tmp_path / "state.json"
    path.write_text(json.dumps(doc))
    return path


def test_in_sync(tmp_path):
    code = _code(tmp_path, "aws_s3_bucket.a")
    state = _state(tmp_path, "aws_s3_bucket.a")
    report = detect_drift(code, state)
    assert report.in_sync == ["aws_s3_bucket.a"]
    assert not report.has_drift


def test_missing_resource(tmp_path):
    code = _code(tmp_path, "aws_s3_bucket.a", "aws_instance.b")
    state = _state(tmp_path, "aws_s3_bucket.a")
    report = detect_drift(code, state)
    assert report.missing == ["aws_instance.b"]
    assert report.has_drift


def test_unmanaged_resource(tmp_path):
    code = _code(tmp_path, "aws_s3_bucket.a")
    state = _state(tmp_path, "aws_s3_bucket.a", "aws_instance.rogue")
    report = detect_drift(code, state)
    assert report.unmanaged == ["aws_instance.rogue"]


def test_child_module_addresses(tmp_path):
    code = _code(tmp_path, "aws_s3_bucket.a")
    doc = {
        "values": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {"resources": [{"address": "module.m.aws_s3_bucket.a",
                                    "type": "aws_s3_bucket", "name": "a"}]}
                ],
            }
        }
    }
    state = tmp_path / "s.json"
    state.write_text(json.dumps(doc))
    report = detect_drift(code, state)
    assert "aws_s3_bucket.a" in report.in_sync


def test_bad_state_raises(tmp_path):
    code = _code(tmp_path, "aws_s3_bucket.a")
    bad = tmp_path / "bad.json"
    bad.write_text("not json{")
    with pytest.raises(DriftError):
        detect_drift(code, bad)


class TestDriftCLI:
    def test_drift_exit_codes(self, tmp_path, capsys):
        code = _code(tmp_path, "aws_s3_bucket.a", "aws_instance.b")
        state = _state(tmp_path, "aws_s3_bucket.a")
        assert main(["drift", str(code), str(state)]) == EXIT_FINDINGS
        assert "MISSING" in capsys.readouterr().out

    def test_drift_clean(self, tmp_path, capsys):
        code = _code(tmp_path, "aws_s3_bucket.a")
        state = _state(tmp_path, "aws_s3_bucket.a")
        assert main(["drift", str(code), str(state)]) == EXIT_OK

    def test_missing_state_file(self, tmp_path, capsys):
        code = _code(tmp_path, "aws_s3_bucket.a")
        assert main(["drift", str(code), str(tmp_path / "nope.json")]) == EXIT_ERROR
