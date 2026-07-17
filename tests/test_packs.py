"""Policy packs: extends resolution, merge semantics, traversal safety."""

from pathlib import Path

import pytest

from cairn.findings import Severity
from cairn.policy import ConfigError, load_config


def _write(tmp_path: Path, text: str) -> Path:
    (tmp_path / ".cairn.yaml").write_text(text)
    return tmp_path


class TestBundledPacks:
    def test_strict_security_loads_and_user_overrides_win(self, tmp_path: Path):
        config = load_config(
            search_dir=_write(tmp_path, "extends: [strict-security]\nfail_on: HIGH\n")
        )
        assert config.severity_overrides["SEC010"] is Severity.CRITICAL  # from pack
        assert config.fail_on is Severity.HIGH  # user wins over pack's MEDIUM

    def test_cost_guard_provides_budget(self, tmp_path: Path):
        config = load_config(search_dir=_write(tmp_path, "extends: cost-guard\n"))
        assert config.budget.max_monthly_increase == 500

    def test_two_packs_merge_in_order(self, tmp_path: Path):
        config = load_config(
            search_dir=_write(tmp_path, "extends: [strict-security, cost-guard]\n")
        )
        assert config.severity_overrides["SEC009"] is Severity.HIGH
        assert config.severity_overrides["COST001"] is Severity.HIGH

    def test_unknown_pack_fails_loudly(self, tmp_path: Path):
        with pytest.raises(ConfigError, match="unknown bundled pack"):
            load_config(search_dir=_write(tmp_path, "extends: [does-not-exist]\n"))


class TestRelativePacks:
    def test_relative_pack_inside_config_dir(self, tmp_path: Path):
        (tmp_path / "team-pack.yaml").write_text("disabled_rules: [GOV001]\n")
        config = load_config(
            search_dir=_write(tmp_path, "extends: [team-pack.yaml]\n")
        )
        assert "GOV001" in config.disabled_rules

    def test_absolute_path_refused(self, tmp_path: Path):
        with pytest.raises(ConfigError, match="must be relative"):
            load_config(search_dir=_write(tmp_path, "extends: [/etc/pack.yaml]\n"))

    def test_escape_via_dotdot_refused(self, tmp_path: Path):
        nested = tmp_path / "nested"
        nested.mkdir()
        (tmp_path / "outside.yaml").write_text("fail_on: INFO\n")
        (nested / ".cairn.yaml").write_text("extends: [../outside.yaml]\n")
        with pytest.raises(ConfigError, match="escapes the config directory"):
            load_config(search_dir=nested)

    def test_pack_extending_pack_refused(self, tmp_path: Path):
        (tmp_path / "meta.yaml").write_text("extends: [strict-security]\n")
        with pytest.raises(ConfigError, match="may not itself use extends"):
            load_config(search_dir=_write(tmp_path, "extends: [meta.yaml]\n"))

    def test_missing_relative_pack_fails(self, tmp_path: Path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(search_dir=_write(tmp_path, "extends: [nope.yaml]\n"))


class TestPackTraversalHardening:
    def test_symlinked_pack_escaping_dir_is_refused(self, tmp_path: Path):
        import os

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.yaml").write_text("fail_on: INFO\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        if not hasattr(os, "symlink"):
            pytest.skip("no symlink support")
        try:
            (repo / "link.yaml").symlink_to(outside / "secret.yaml")
        except OSError:
            pytest.skip("symlinks not permitted")
        (repo / ".cairn.yaml").write_text("extends: [link.yaml]\n")
        with pytest.raises(ConfigError, match="escapes the config directory"):
            load_config(search_dir=repo)

    def test_non_yaml_extends_is_refused(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text("extends: [evil.py]\n")
        with pytest.raises(ConfigError, match="bundled pack names or relative"):
            load_config(search_dir=tmp_path)
