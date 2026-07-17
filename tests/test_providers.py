"""Provider inference, the provider dimension on findings, and filtering."""


from cairn.engine import run_scan
from cairn.policy import Config
from cairn.providers import provider_for

from .conftest import REPO_ROOT

EX = REPO_ROOT / "examples"


class TestProviderInference:
    def test_prefix_mapping(self):
        assert provider_for("aws_instance") == "aws"
        assert provider_for("azurerm_managed_disk") == "azure"
        assert provider_for("google_compute_instance") == "gcp"
        assert provider_for("vsphere_virtual_machine") == "vsphere"
        assert provider_for("k8s_deployment") == "kubernetes"
        assert provider_for("random_pet") == "other"


class TestFindingsCarryProvider:
    def test_aws_findings_tagged_aws(self):
        result = run_scan(EX / "vulnerable", Config())
        assert result.findings
        assert all(f.provider == "aws" for f in result.findings)

    def test_azure_findings_tagged_azure(self):
        result = run_scan(EX / "azure" / "vulnerable.tf", Config())
        assert result.findings
        assert all(f.provider == "azure" for f in result.findings)


class TestProviderFilter:
    def test_filter_keeps_only_requested(self, tmp_path):
        (tmp_path / "az.tf").write_text((EX / "azure" / "vulnerable.tf").read_text())
        (tmp_path / "gcp.tf").write_text((EX / "gcp" / "vulnerable.tf").read_text())
        allp = run_scan(tmp_path, Config())
        azure = run_scan(tmp_path, Config(), providers=("azure",))
        assert {f.provider for f in allp.findings} == {"azure", "gcp"}
        assert {f.provider for f in azure.findings} == {"azure"}
        assert len(azure.findings) < len(allp.findings)


class TestMultiCloudRules:
    def test_azure_families_fire(self):
        ids = {f.rule_id for f in run_scan(EX / "azure" / "vulnerable.tf", Config()).findings}
        assert {"AZ001", "AZ002", "AZ003", "AZ004", "AZ005", "AZ006"} <= ids

    def test_gcp_families_fire(self):
        ids = {f.rule_id for f in run_scan(EX / "gcp" / "vulnerable.tf", Config()).findings}
        assert {"GCP001", "GCP002", "GCP003", "GCP004", "GCP005", "GCP006"} <= ids

    def test_vsphere_families_fire(self):
        ids = {f.rule_id for f in run_scan(EX / "vsphere" / "vulnerable.tf", Config()).findings}
        assert {"VS001", "VS002", "VS003"} <= ids

    def test_vsphere_clean_is_clean(self):
        assert run_scan(EX / "vsphere" / "clean.tf", Config()).findings == []

    def test_azure_ssh_is_critical(self):
        from cairn.findings import Severity

        findings = run_scan(EX / "azure" / "vulnerable.tf", Config()).findings
        az001 = [f for f in findings if f.rule_id == "AZ001"]
        assert az001 and az001[0].severity is Severity.CRITICAL

    def test_azure_vm_cost_estimate(self):
        findings = run_scan(EX / "azure" / "vulnerable.tf", Config()).findings
        az005 = [f for f in findings if f.rule_id == "AZ005"]
        assert az005 and az005[0].monthly_cost == 560.0

    def test_gcp_machine_cost_estimate(self):
        findings = run_scan(EX / "gcp" / "vulnerable.tf", Config()).findings
        gcp005 = [f for f in findings if f.rule_id == "GCP005"]
        assert gcp005 and gcp005[0].monthly_cost == 560.0
