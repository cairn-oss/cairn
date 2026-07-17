"""Cost simulation and the budget gate."""

from pathlib import Path

from cairn.cli import EXIT_FINDINGS, EXIT_OK, main
from cairn.costs import diff_costs


def _dirs(tmp_path: Path, old: str, new: str) -> tuple[Path, Path]:
    old_dir, new_dir = tmp_path / "old", tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()
    (old_dir / "main.tf").write_text(old)
    (new_dir / "main.tf").write_text(new)
    return old_dir, new_dir


class TestDiffCosts:
    def test_added_changed_and_totals(self, tmp_path: Path):
        old, new = _dirs(
            tmp_path,
            'resource "aws_instance" "web" { instance_type = "t3.large" }\n',
            'resource "aws_instance" "web" { instance_type = "m5.xlarge" }\n'
            'resource "aws_ebs_volume" "v" { size = 100\n type = "gp3" }\n',
        )
        diff = diff_costs(old, new)
        assert [a for a, _ in diff.added] == ["aws_ebs_volume.v"]
        assert [a for a, _, _ in diff.changed] == ["aws_instance.web"]
        assert diff.delta > 0

    def test_multi_az_doubles_rds(self, tmp_path: Path):
        old, new = _dirs(
            tmp_path,
            'resource "aws_db_instance" "db" { instance_class = "db.m5.large" }\n',
            'resource "aws_db_instance" "db" {\n'
            '  instance_class = "db.m5.large"\n  multi_az = true\n}\n',
        )
        diff = diff_costs(old, new)
        (_address, before, after), = diff.changed
        assert after == before * 2

    def test_unpriced_resources_reported_not_guessed(self, tmp_path: Path):
        old, new = _dirs(
            tmp_path, "", 'resource "aws_lambda_function" "f" { function_name = "x" }\n'
        )
        diff = diff_costs(old, new)
        assert diff.unpriced == ["aws_lambda_function.f"]
        assert diff.delta == 0


class TestBudgetGate:
    def test_breach_exits_1(self, tmp_path: Path, capsys):
        old, new = _dirs(
            tmp_path,
            "",
            'resource "aws_instance" "big" { instance_type = "m5.4xlarge" }\n',
        )
        config = tmp_path / "cfg.yaml"
        config.write_text("budget:\n  max_monthly_increase: 100\n")
        assert main(["diff", str(old), str(new), "--config", str(config)]) == EXIT_FINDINGS
        assert "BREACHES" in capsys.readouterr().out

    def test_within_budget_exits_0(self, tmp_path: Path, capsys):
        old, new = _dirs(
            tmp_path, "", 'resource "aws_ebs_volume" "v" { size = 10\n type = "gp3" }\n'
        )
        config = tmp_path / "cfg.yaml"
        config.write_text("budget:\n  max_monthly_increase: 100\n")
        assert main(["diff", str(old), str(new), "--config", str(config)]) == EXIT_OK

    def test_no_budget_is_informational(self, tmp_path: Path, capsys):
        old, new = _dirs(
            tmp_path, "", 'resource "aws_instance" "big" { instance_type = "m5.4xlarge" }\n'
        )
        assert main(["diff", str(old), str(new)]) == EXIT_OK


class TestRenderCostDiff:
    def test_removed_and_no_change_render(self, tmp_path: Path):
        from cairn.costs import diff_costs, render_cost_diff

        old, new = _dirs(
            tmp_path,
            'resource "aws_instance" "gone" { instance_type = "t3.large" }\n',
            "",
        )
        text = render_cost_diff(diff_costs(old, new), budget_limit=None)
        assert "- aws_instance.gone" in text
        assert "Total:" in text

    def test_no_priced_change_line(self, tmp_path: Path):
        from cairn.costs import diff_costs, render_cost_diff

        old, new = _dirs(tmp_path, "", "")
        text = render_cost_diff(diff_costs(old, new), budget_limit=100)
        assert "no priced resources changed" in text
        assert "within the configured limit" in text
