from cairn.engine import reconcile, run_scan
from cairn.findings import Category, Finding, Severity
from cairn.policy import Config

from .conftest import EXAMPLES


def _finding(category: Category, address: str = "aws_instance.a") -> Finding:
    rtype, name = address.split(".", 1)
    return Finding(
        rule_id="X001",
        severity=Severity.MEDIUM,
        category=category,
        resource_type=rtype,
        resource_name=name,
        file="main.tf",
        line=1,
        message="m",
        fix="f",
    )


class TestReconcile:
    def test_cost_plus_security_produces_trade_off(self):
        trade_offs = reconcile(
            [_finding(Category.COST), _finding(Category.SECURITY)]
        )
        assert len(trade_offs) == 1
        assert "security fix first" in trade_offs[0].note

    def test_cost_plus_reliability_produces_trade_off(self):
        trade_offs = reconcile(
            [_finding(Category.COST), _finding(Category.RELIABILITY)]
        )
        assert len(trade_offs) == 1
        assert "resilience" in trade_offs[0].note

    def test_single_discipline_no_trade_off(self):
        assert reconcile([_finding(Category.COST)]) == []

    def test_different_resources_do_not_collide(self):
        trade_offs = reconcile(
            [
                _finding(Category.COST, "aws_instance.a"),
                _finding(Category.SECURITY, "aws_instance.b"),
            ]
        )
        assert trade_offs == []


class TestRunScan:
    def test_vulnerable_example_finds_planted_issues(self):
        result = run_scan(EXAMPLES / "vulnerable", Config())
        ids = {f.rule_id for f in result.findings}
        # every rule family fires at least once on the fixture
        assert {"SEC001", "SEC002", "SEC004", "SEC005", "SEC006", "SEC007",
                "SEC008", "SEC009", "COST001", "COST002", "COST003", "COST004",
                "COST005", "REL001", "REL002", "GOV001"} <= ids
        assert result.estimated_monthly_savings > 1000
        assert result.trade_offs  # fusion fires
        assert result.parse_errors == []

    def test_clean_example_is_clean(self):
        result = run_scan(EXAMPLES / "clean", Config())
        assert result.findings == []
        assert result.resources_scanned > 0

    def test_findings_are_severity_sorted(self):
        result = run_scan(EXAMPLES / "vulnerable", Config())
        ranks = [f.severity.rank for f in result.findings]
        assert ranks == sorted(ranks)

    def test_policy_flows_through_engine(self):
        config = Config(min_severity=Severity.CRITICAL)
        result = run_scan(EXAMPLES / "vulnerable", Config()), run_scan(
            EXAMPLES / "vulnerable", config
        )
        unfiltered, filtered = result
        assert 0 < len(filtered.findings) < len(unfiltered.findings)
        assert all(f.severity is Severity.CRITICAL for f in filtered.findings)
