from pathlib import Path

import pytest

from cairn.findings import Category, Finding, Severity
from cairn.policy import Config, ConfigError, Ignore, load_config


def _finding(rule_id="SEC001", severity=Severity.HIGH, name="web") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=Category.SECURITY,
        resource_type="aws_security_group",
        resource_name=name,
        file="main.tf",
        line=1,
        message="m",
        fix="f",
    )


class TestApply:
    def test_disabled_rule_is_dropped(self):
        config = Config(disabled_rules=("SEC001",))
        assert config.apply([_finding()]) == []

    def test_ignore_by_rule_and_resource_glob(self):
        config = Config(ignores=(Ignore(rule="SEC*", resource="aws_security_group.legacy_*"),))
        kept = _finding(name="web")
        ignored = _finding(name="legacy_a")
        assert config.apply([kept, ignored]) == [kept]

    def test_severity_override(self):
        config = Config(severity_overrides={"SEC001": Severity.LOW})
        (result,) = config.apply([_finding()])
        assert result.severity is Severity.LOW

    def test_min_severity_floor(self):
        config = Config(min_severity=Severity.HIGH)
        high = _finding(severity=Severity.HIGH)
        low = _finding(rule_id="GOV001", severity=Severity.LOW)
        assert config.apply([high, low]) == [high]

    def test_override_then_floor_interact(self):
        # Downgraded below the floor -> dropped. Policy is applied in order.
        config = Config(
            severity_overrides={"SEC001": Severity.INFO}, min_severity=Severity.LOW
        )
        assert config.apply([_finding()]) == []


class TestShouldFail:
    def test_fail_on_threshold(self):
        config = Config(fail_on=Severity.HIGH)
        assert config.should_fail([_finding(severity=Severity.CRITICAL)])
        assert not config.should_fail([_finding(severity=Severity.MEDIUM)])

    def test_fail_never(self):
        config = Config(fail_never=True)
        assert not config.should_fail([_finding(severity=Severity.CRITICAL)])


class TestLoadConfig:
    def test_defaults_when_no_file(self, tmp_path: Path):
        config = load_config(search_dir=tmp_path)
        assert config.fail_on is Severity.HIGH
        assert config.source == "(defaults)"

    def test_discovers_dot_cairn_yaml(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text(
            "min_severity: MEDIUM\nfail_on: CRITICAL\nrequired_tags: [Owner]\n"
        )
        config = load_config(search_dir=tmp_path)
        assert config.min_severity is Severity.MEDIUM
        assert config.fail_on is Severity.CRITICAL
        assert config.required_tags == ("Owner",)

    def test_full_config_parses(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text(
            """
min_severity: LOW
disabled_rules: [GOV001]
severity_overrides:
  COST002: HIGH
ignores:
  - rule: SEC001
    resource: aws_security_group.legacy
    reason: grandfathered
llm:
  provider: ollama
  model: llama3.1
audit:
  enabled: false
"""
        )
        config = load_config(search_dir=tmp_path)
        assert config.disabled_rules == ("GOV001",)
        assert config.severity_overrides["COST002"] is Severity.HIGH
        assert config.ignores[0].reason == "grandfathered"
        assert config.llm.provider == "ollama"
        assert config.audit.enabled is False

    def test_unknown_key_fails_loudly(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text("min_severty: LOW\n")
        with pytest.raises(ConfigError, match="unknown key"):
            load_config(search_dir=tmp_path)

    def test_bad_severity_fails_loudly(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text("fail_on: EXTREME\n")
        with pytest.raises(ConfigError, match="unknown severity"):
            load_config(search_dir=tmp_path)

    def test_invalid_yaml_fails_loudly(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text("a: [unclosed\n")
        with pytest.raises(ConfigError, match="invalid YAML"):
            load_config(search_dir=tmp_path)

    def test_explicit_missing_file_fails(self, tmp_path: Path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(explicit=tmp_path / "nope.yaml")


class TestAuditPathValidation:
    def test_non_jsonl_audit_path_fails_loudly(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text('audit:\n  path: ~/.bashrc\n')
        with pytest.raises(ConfigError, match=r"audit\.path must end in \.jsonl"):
            load_config(search_dir=tmp_path)

    def test_jsonl_audit_path_accepted(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text('audit:\n  path: ./scan-log.jsonl\n')
        config = load_config(search_dir=tmp_path)
        assert config.audit.path == "./scan-log.jsonl"


class TestAutonomyConfig:
    def test_default_is_empty(self, tmp_path: Path):
        assert load_config(search_dir=tmp_path).autonomy.allow == ()

    def test_grants_parsed(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text("autonomy:\n  allow: [volume-types, encryption]\n")
        cfg = load_config(search_dir=tmp_path)
        assert cfg.autonomy.allow == ("volume-types", "encryption")

    def test_non_list_allow_fails(self, tmp_path: Path):
        (tmp_path / ".cairn.yaml").write_text("autonomy:\n  allow: volume-types\n")
        with pytest.raises(ConfigError, match=r"autonomy\.allow must be a list"):
            load_config(search_dir=tmp_path)
