import json
from pathlib import Path

from cairn.audit import record_scan
from cairn.policy import AuditConfig


def _record(config: AuditConfig) -> None:
    record_scan(
        config,
        target="examples/vulnerable",
        files_scanned=1,
        resources_scanned=8,
        findings_by_severity={"CRITICAL": 4},
        duration_seconds=0.123,
        exit_code=1,
    )


def test_writes_append_only_jsonl(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    config = AuditConfig(enabled=True, path=str(log))
    _record(config)
    _record(config)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    entry = json.loads(lines[0])
    assert entry["action"] == "scan"
    assert entry["trust_level"] == "read-only"
    assert entry["findings_by_severity"] == {"CRITICAL": 4}
    assert "ts" in entry and "cairn_version" in entry


def test_disabled_writes_nothing(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _record(AuditConfig(enabled=False, path=str(log)))
    assert not log.exists()


def test_unwritable_path_never_raises():
    _record(AuditConfig(enabled=True, path="/proc/definitely/not/writable/x.jsonl"))


def test_non_jsonl_path_is_refused(tmp_path):
    target = tmp_path / "bashrc"  # simulates a shell rc file
    _record(AuditConfig(enabled=True, path=str(target)))
    assert not target.exists()


def test_symlink_target_is_refused(tmp_path):
    import os

    import pytest

    if not hasattr(os, "symlink"):
        pytest.skip("no symlink support")
    real = tmp_path / "real.jsonl"
    real.write_text("")
    link = tmp_path / "log.jsonl"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks not permitted")
    _record(AuditConfig(enabled=True, path=str(link)))
    assert real.read_text() == ""
