"""End-to-end CLI tests: the exit-code contract is what CI relies on."""

import json
from pathlib import Path

from cairn.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

from .conftest import EXAMPLES

VULN = str(EXAMPLES / "vulnerable")
CLEAN = str(EXAMPLES / "clean")


def _no_audit(tmp_path: Path) -> str:
    config = tmp_path / "cfg.yaml"
    config.write_text("audit:\n  enabled: false\n")
    return str(config)


class TestExitCodes:
    def test_findings_above_threshold_exit_1(self, tmp_path, capsys):
        assert main(["scan", VULN, "--config", _no_audit(tmp_path)]) == EXIT_FINDINGS

    def test_clean_target_exit_0(self, tmp_path, capsys):
        assert main(["scan", CLEAN, "--config", _no_audit(tmp_path)]) == EXIT_OK

    def test_fail_on_never_reports_but_passes(self, tmp_path, capsys):
        code = main(
            ["scan", VULN, "--config", _no_audit(tmp_path), "--fail-on", "NEVER"]
        )
        assert code == EXIT_OK
        assert "CRITICAL" in capsys.readouterr().out

    def test_fail_on_critical_only(self, tmp_path, capsys):
        # vulnerable fixture has CRITICALs, so still fails
        code = main(
            ["scan", VULN, "--config", _no_audit(tmp_path), "--fail-on", "CRITICAL"]
        )
        assert code == EXIT_FINDINGS

    def test_min_severity_filters_report(self, tmp_path, capsys):
        main(
            ["scan", VULN, "--config", _no_audit(tmp_path),
             "--min-severity", "CRITICAL", "--fail-on", "NEVER"]
        )
        out = capsys.readouterr().out
        assert "CRITICAL" in out and "LOW/" not in out

    def test_nonexistent_path_exit_2(self, capsys):
        assert main(["scan", "/does/not/exist"]) == EXIT_ERROR
        assert "does not exist" in capsys.readouterr().err

    def test_broken_config_exit_2(self, tmp_path, capsys):
        config = tmp_path / "bad.yaml"
        config.write_text("fail_on: EXTREME\n")
        assert main(["scan", VULN, "--config", str(config)]) == EXIT_ERROR
        assert "configuration error" in capsys.readouterr().err

    def test_bad_severity_flag_exit_2(self, tmp_path, capsys):
        code = main(
            ["scan", VULN, "--config", _no_audit(tmp_path), "--fail-on", "MEGA"]
        )
        assert code == EXIT_ERROR


class TestOutputs:
    def test_json_format_to_file(self, tmp_path, capsys):
        out_file = tmp_path / "report.json"
        main(
            ["scan", VULN, "--config", _no_audit(tmp_path), "--format", "json",
             "--output", str(out_file), "--fail-on", "NEVER"]
        )
        data = json.loads(out_file.read_text())
        assert data["schema_version"] == 2
        assert data["summary"]["findings"] > 0

    def test_quiet_suppresses_stdout(self, tmp_path, capsys):
        main(["scan", VULN, "--config", _no_audit(tmp_path), "--quiet",
              "--fail-on", "NEVER"])
        assert capsys.readouterr().out == ""

    def test_quiet_still_writes_requested_output_file(self, tmp_path, capsys):
        out_file = tmp_path / "r.json"
        main(["scan", VULN, "--config", _no_audit(tmp_path), "--quiet",
              "--format", "json", "--output", str(out_file), "--fail-on", "NEVER"])
        assert out_file.exists()
        assert capsys.readouterr().out == ""

    def test_explain_without_provider_is_a_clear_error(self, tmp_path, capsys):
        code = main(["scan", VULN, "--config", _no_audit(tmp_path), "--explain"])
        assert code == EXIT_ERROR
        assert "opt-in" in capsys.readouterr().err


class TestOtherCommands:
    def test_rules_lists_all(self, capsys):
        assert main(["rules"]) == EXIT_OK
        out = capsys.readouterr().out
        for rule_id in ("SEC001", "COST001", "REL001", "GOV001"):
            assert rule_id in out

    def test_rules_markdown(self, capsys):
        assert main(["rules", "--format", "markdown"]) == EXIT_OK
        assert "| SEC001 |" in capsys.readouterr().out

    def test_version(self, capsys):
        assert main(["version"]) == EXIT_OK
        assert "cairn" in capsys.readouterr().out
