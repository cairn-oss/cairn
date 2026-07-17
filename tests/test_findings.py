from cairn.findings import Category, Finding, Severity, sort_findings


def _finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="SEC001",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource_type="aws_instance",
        resource_name="web",
        file="main.tf",
        line=3,
        message="msg",
        fix="fix",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestSeverity:
    def test_ordering_most_severe_first(self):
        ranks = [s.rank for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                                  Severity.LOW, Severity.INFO)]
        assert ranks == sorted(ranks)

    def test_at_least(self):
        assert Severity.CRITICAL.at_least(Severity.HIGH)
        assert Severity.HIGH.at_least(Severity.HIGH)
        assert not Severity.MEDIUM.at_least(Severity.HIGH)

    def test_from_str_case_insensitive(self):
        assert Severity.from_str("high") is Severity.HIGH
        assert Severity.from_str(" CRITICAL ") is Severity.CRITICAL

    def test_from_str_invalid(self):
        import pytest

        with pytest.raises(ValueError, match="unknown severity"):
            Severity.from_str("BANANAS")


class TestFinding:
    def test_address(self):
        assert _finding().address == "aws_instance.web"

    def test_to_dict_round_trips_severity_and_cost(self):
        d = _finding(monthly_cost=12.5, references=("https://x",)).to_dict()
        assert d["severity"] == "HIGH"
        assert d["monthly_cost_usd"] == 12.5
        assert d["references"] == ["https://x"]
        assert d["resource"] == "aws_instance.web"

    def test_sort_by_severity_then_location(self):
        low = _finding(severity=Severity.LOW, line=1)
        crit = _finding(severity=Severity.CRITICAL, line=9)
        med_a = _finding(severity=Severity.MEDIUM, file="a.tf")
        med_b = _finding(severity=Severity.MEDIUM, file="b.tf")
        ordered = sort_findings([low, med_b, crit, med_a])
        assert ordered == [crit, med_a, med_b, low]
