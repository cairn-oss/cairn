import json

from cairn.engine import run_scan
from cairn.policy import Config
from cairn.report import render_console, render_json, render_markdown, render_sarif

from .conftest import EXAMPLES


def _result():
    return run_scan(EXAMPLES / "vulnerable", Config())


def _clean_result():
    return run_scan(EXAMPLES / "clean", Config())


class TestConsole:
    def test_contains_findings_and_summary(self):
        out = render_console(_result())
        assert "CRITICAL/SECURITY" in out
        assert "Estimated recoverable spend" in out
        assert "Trade-offs" in out
        assert "nothing left this machine" in out

    def test_no_ansi_when_color_off(self):
        assert "\033[" not in render_console(_result(), color=False)

    def test_ansi_when_color_on(self):
        assert "\033[" in render_console(_result(), color=True)

    def test_clean_message(self):
        assert "no findings. Clean." in render_console(_clean_result())

    def test_explanations_are_rendered(self):
        result = _result()
        finding = result.findings[0]
        out = render_console(result, explanations={finding: "Because reasons."})
        assert "cairn says:" in out
        assert "Because reasons." in out


class TestJson:
    def test_valid_json_with_stable_schema(self):
        data = json.loads(render_json(_result()))
        assert data["schema_version"] == 2
        assert data["summary"]["findings"] == len(data["findings"])
        assert data["summary"]["estimated_monthly_savings_usd"] > 0
        first = data["findings"][0]
        for key in ("rule_id", "severity", "category", "resource", "file",
                    "line", "message", "fix", "monthly_cost_usd"):
            assert key in first
        assert data["trade_offs"]


class TestSarif:
    def test_valid_sarif_2_1_0(self):
        data = json.loads(render_sarif(_result()))
        assert data["version"] == "2.1.0"
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Cairn"
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in rule_ids
            assert result["level"] in ("error", "warning", "note")
            region = result["locations"][0]["physicalLocation"]["region"]
            assert region["startLine"] >= 1

    def test_severity_maps_to_sarif_levels(self):
        data = json.loads(render_sarif(_result()))
        levels = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
        assert levels["SEC004"] == "error"   # CRITICAL
        assert levels["GOV001"] == "note"    # LOW


class TestMarkdown:
    def test_structure(self):
        out = render_markdown(_result())
        assert out.startswith("# Cairn scan report")
        assert "| # | Severity |" in out
        assert "## Fixes" in out
        assert "```hcl" in out
        assert "Trade-offs" in out

    def test_clean(self):
        assert "No findings" in render_markdown(_clean_result())


class TestHtml:
    def test_self_contained_document(self):
        from cairn.report.html import render_html

        out = render_html(_result())
        assert out.startswith("<!doctype html")
        assert "CRITICAL" in out and "Trade-offs" in out
        assert "http://" not in out and "https://" not in out  # zero external assets

    def test_untrusted_strings_are_escaped(self, tmp_path):
        from pathlib import Path

        from cairn.engine import run_scan
        from cairn.policy import Config
        from cairn.report.html import render_html

        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "xss" {\n'
            '  bucket = "<script>alert(1)</script>"\n}\n'
        )
        out = render_html(run_scan(Path(tmp_path), Config()))
        assert "<script>alert" not in out


class TestHtmlEdges:
    def test_clean_scan_renders_clean_document(self):
        from cairn.report.html import render_html

        out = render_html(_clean_result())
        assert "No findings. Clean." in out
        assert out.strip().endswith("</html>")

    def test_warnings_and_suppressions_render(self, tmp_path):
        from pathlib import Path

        from cairn.engine import run_scan
        from cairn.policy import Config
        from cairn.report.html import render_html

        (tmp_path / "main.tf").write_text(
            "resource \"aws_security_group\" \"s\" {\n"
            "  ingress {\n"
            "    # cairn:ignore SEC001 reason=documented\n"
            "    from_port   = 22\n    to_port = 22\n    protocol = \"tcp\"\n"
            "    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n  tags = { Name = \"s\" }\n}\n"
        )
        out = render_html(run_scan(Path(tmp_path), Config()))
        assert "suppressed" in out
