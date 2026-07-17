"""Coverage transparency: never call an unsupported-provider scan 'clean'."""

import json
from pathlib import Path

from cairn.cli import EXIT_OK, main
from cairn.engine import run_scan
from cairn.policy import Config
from cairn.report import render_console, render_json


def _scan(tmp_path: Path, source: str, name: str = "main.tf"):
    (tmp_path / name).write_text(source)
    return run_scan(tmp_path, Config())


UNSUPPORTED = (
    'resource "oci_core_instance" "vm" { shape = "VM.Standard2.4" }\n'
    'resource "digitalocean_droplet" "web" { size = "s-4vcpu-8gb" }\n'
)
AWS_CLEAN = (
    'resource "aws_s3_bucket" "b" {\n'
    '  tags = { Name = "b", Environment = "prod", Owner = "t" }\n}\n'
    'resource "aws_s3_bucket_versioning" "b" {\n'
    '  bucket = aws_s3_bucket.b.id\n'
    '  versioning_configuration { status = "Enabled" }\n}\n'
    'resource "aws_s3_bucket_server_side_encryption_configuration" "b" {\n'
    '  bucket = aws_s3_bucket.b.id\n}\n'
)


class TestCoverageModel:
    def test_unsupported_provider_is_uncovered(self, tmp_path):
        result = _scan(tmp_path, UNSUPPORTED)
        assert not result.fully_covered
        assert result.covered_resources == 0
        assert set(result.uncovered_types) == {"oci_core_instance", "digitalocean_droplet"}

    def test_supported_provider_companions_are_covered(self, tmp_path):
        # AWS companion resources (versioning, encryption config) have no
        # dedicated rule but belong to a covered provider -> not a gap.
        result = _scan(tmp_path, AWS_CLEAN)
        assert result.fully_covered
        assert result.uncovered == []

    def test_uncovered_by_provider_breakdown(self, tmp_path):
        result = _scan(tmp_path, UNSUPPORTED)
        assert result.uncovered_by_provider == {"oracle-cloud": 1, "digitalocean": 1}


class TestConsoleHonesty:
    def test_clean_only_when_fully_covered(self, tmp_path):
        out = render_console(_scan(tmp_path, AWS_CLEAN))
        assert "Clean." in out
        assert "Not scanned" not in out

    def test_no_clean_claim_for_unsupported(self, tmp_path):
        out = render_console(_scan(tmp_path, UNSUPPORTED))
        assert "Clean." not in out
        assert "Not scanned:" in out
        assert "coverage gap, not a clean result" in out

    def test_gap_lists_types_and_guidance(self, tmp_path):
        out = render_console(_scan(tmp_path, UNSUPPORTED))
        assert "oci_core_instance" in out
        assert "cairn providers" in out


class TestJsonCoverage:
    def test_coverage_block_present(self, tmp_path):
        data = json.loads(render_json(_scan(tmp_path, UNSUPPORTED)))
        cov = data["coverage"]
        assert cov["fully_covered"] is False
        assert cov["uncovered_count"] == 2
        assert "oci_core_instance" in cov["uncovered_types"]
        assert data["summary"]["covered_resources"] == 0

    def test_fully_covered_true_for_aws(self, tmp_path):
        data = json.loads(render_json(_scan(tmp_path, AWS_CLEAN)))
        assert data["coverage"]["fully_covered"] is True


class TestProvidersCommand:
    def test_providers_lists_covered(self, capsys):
        assert main(["providers"]) == EXIT_OK
        out = capsys.readouterr().out
        for provider in ("aws", "azure", "gcp", "kubernetes"):
            assert provider in out
        assert "on-prem" in out

    def test_provider_inference_tiers(self):
        from cairn.providers import is_covered, provider_for

        assert provider_for("aws_instance") == "aws" and is_covered("aws_instance")
        assert provider_for("oci_core_instance") == "oracle-cloud"
        assert not is_covered("oci_core_instance")
        assert provider_for("digitalocean_droplet") == "digitalocean"
        assert provider_for("something_unknown") == "other"
