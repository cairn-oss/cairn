"""Guarded autonomy (Trust Ladder rung 2): whitelist, grants, git safety."""

import os
import subprocess
from pathlib import Path

import pytest

from cairn.autofix import AutofixError, eligible_findings, plan_fixes
from cairn.cli import EXIT_ERROR, EXIT_OK, main
from cairn.engine import run_scan
from cairn.policy import Config


def _git_repo(tmp_path: Path, tf: str) -> Path:
    (tmp_path / "main.tf").write_text(tf)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@x.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "init"], check=True)
    return tmp_path


GP2 = (
    'resource "aws_ebs_volume" "v" {\n'
    '  availability_zone = "us-east-1a"\n'
    '  size = 100\n  type = "gp2"\n  encrypted = true\n'
    '  tags = { Name = "v", Environment = "prod", Owner = "p" }\n}\n'
)


class TestEligibility:
    def test_only_whitelisted_and_granted(self, tmp_path):
        repo = _git_repo(tmp_path, GP2)
        result = run_scan(repo, Config())
        # COST002 is whitelisted; only eligible when its category is granted
        assert eligible_findings(result, ()) == []
        granted = eligible_findings(result, ("volume-types",))
        assert [f.rule_id for f in granted] == ["COST002"]


class TestDryRunAndApply:
    def test_dry_run_writes_nothing(self, tmp_path):
        repo = _git_repo(tmp_path, GP2)
        result = run_scan(repo, Config())
        plan = plan_fixes(result, ("volume-types",), apply=False, root=repo)
        assert len(plan.applied) == 1  # planned
        assert 'type = "gp2"' in (repo / "main.tf").read_text()  # not written

    def test_apply_writes_and_hashes_change(self, tmp_path):
        repo = _git_repo(tmp_path, GP2)
        result = run_scan(repo, Config())
        plan = plan_fixes(result, ("volume-types",), apply=True, root=repo)
        applied = plan.applied[0]
        assert applied.before_sha != applied.after_sha
        text = (repo / "main.tf").read_text()
        assert 'type = "gp3"' in text and "gp2" not in text

    def test_apply_is_atomic_and_preserves_mode(self, tmp_path):
        repo = _git_repo(tmp_path, GP2)
        target = repo / "main.tf"
        os.chmod(target, 0o640)
        mode_before = target.stat().st_mode
        result = run_scan(repo, Config())
        plan_fixes(result, ("volume-types",), apply=True, root=repo)
        assert 'type = "gp3"' in target.read_text()  # content changed
        assert target.stat().st_mode == mode_before  # mode preserved by _atomic_write
        assert list(repo.glob(".cairn-*.tmp")) == []  # no temp file left behind

    def test_apply_refuses_dirty_worktree(self, tmp_path):
        repo = _git_repo(tmp_path, GP2)
        (repo / "main.tf").write_text(GP2 + "# uncommitted change\n")
        result = run_scan(repo, Config())
        with pytest.raises(AutofixError, match="clean git worktree"):
            plan_fixes(result, ("volume-types",), apply=True, root=repo)

    def test_apply_refuses_non_git(self, tmp_path):
        (tmp_path / "main.tf").write_text(GP2)
        result = run_scan(tmp_path, Config())
        with pytest.raises(AutofixError):
            plan_fixes(result, ("volume-types",), apply=True, root=tmp_path)


class TestCLI:
    def test_dry_run_default(self, tmp_path, capsys):
        repo = _git_repo(tmp_path, GP2)
        (repo / ".cairn.yaml").write_text(
            "autonomy:\n  allow: [volume-types]\naudit:\n  enabled: false\n"
        )
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "cfg"], check=True)
        assert main(["fix", str(repo)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "Would apply" in out and "Dry run" in out
        assert 'type = "gp2"' in (repo / "main.tf").read_text()

    def test_apply_flag_writes(self, tmp_path, capsys):
        repo = _git_repo(tmp_path, GP2)
        (repo / ".cairn.yaml").write_text(
            "autonomy:\n  allow: [volume-types]\naudit:\n  enabled: false\n"
        )
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "cfg"], check=True)
        assert main(["fix", str(repo), "--apply"]) == EXIT_OK
        assert 'type = "gp3"' in (repo / "main.tf").read_text()

    def test_no_grant_nothing_eligible(self, tmp_path, capsys):
        repo = _git_repo(tmp_path, GP2)
        assert main(["fix", str(repo)]) == EXIT_OK
        assert "no eligible" in capsys.readouterr().out

    def test_missing_path(self, capsys):
        assert main(["fix", "/does/not/exist"]) == EXIT_ERROR
