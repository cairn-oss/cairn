"""Behavioral tests for COST, REL and GOV rules."""

from .conftest import rule_ids


class TestCOST001Oversized:
    def test_4xlarge_flagged_with_savings(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "big" { instance_type = "m5.4xlarge" }'
        )
        match = [f for f in findings if f.rule_id == "COST001"]
        assert match
        assert match[0].monthly_cost and match[0].monthly_cost > 300
        assert "m5.xlarge" in (match[0].fix_code or "")

    def test_small_instance_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "s" { instance_type = "t3.small" }'
        )
        assert "COST001" not in rule_ids(findings)

    def test_unknown_type_does_not_crash(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "x" { instance_type = "z9.4xlarge" }'
        )
        match = [f for f in findings if f.rule_id == "COST001"]
        assert match and match[0].monthly_cost is None


class TestCOST002Gp2:
    def test_gp2_savings_scale_with_size(self, run_rules):
        findings = run_rules(
            'resource "aws_ebs_volume" "v" { type = "gp2"\n size = 1000 }'
        )
        match = [f for f in findings if f.rule_id == "COST002"]
        assert match and match[0].monthly_cost == 20.0

    def test_gp3_clean(self, run_rules):
        findings = run_rules('resource "aws_ebs_volume" "v" { type = "gp3" }')
        assert "COST002" not in rule_ids(findings)


class TestCOST003IdleEip:
    def test_unassociated_eip_flagged(self, run_rules):
        findings = run_rules('resource "aws_eip" "spare" {}')
        assert "COST003" in rule_ids(findings)

    def test_inline_instance_suppresses(self, run_rules):
        findings = run_rules(
            'resource "aws_eip" "used" { instance = aws_instance.web.id }'
        )
        assert "COST003" not in rule_ids(findings)

    def test_association_resource_suppresses(self, run_rules):
        findings = run_rules(
            """
            resource "aws_eip" "used" {}
            resource "aws_eip_association" "a" {
              allocation_id = aws_eip.used.id
              instance_id   = aws_instance.web.id
            }
            """
        )
        assert "COST003" not in rule_ids(findings)


class TestCOST004OversizedRDS:
    def test_4xlarge_class_flagged(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { instance_class = "db.r5.4xlarge" }'
        )
        assert "COST004" in rule_ids(findings)

    def test_medium_class_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { instance_class = "db.t3.medium" }'
        )
        assert "COST004" not in rule_ids(findings)


class TestCOST005OldGeneration:
    def test_t2_suggests_t3(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "old" { instance_type = "t2.large" }'
        )
        match = [f for f in findings if f.rule_id == "COST005"]
        assert match and "t3.large" in match[0].message

    def test_current_generation_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "new" { instance_type = "m5.large" }'
        )
        assert "COST005" not in rule_ids(findings)


class TestREL001Backups:
    def test_zero_retention_flagged(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { backup_retention_period = 0 }'
        )
        assert "REL001" in rule_ids(findings)

    def test_retention_set_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { backup_retention_period = 14 }'
        )
        assert "REL001" not in rule_ids(findings)


class TestREL002Versioning:
    def test_no_versioning_flagged(self, run_rules):
        findings = run_rules('resource "aws_s3_bucket" "b" {}')
        assert "REL002" in rule_ids(findings)

    def test_companion_versioning_suppresses(self, run_rules):
        findings = run_rules(
            """
            resource "aws_s3_bucket" "b" {}
            resource "aws_s3_bucket_versioning" "b" {
              bucket = aws_s3_bucket.b.id
              versioning_configuration { status = "Enabled" }
            }
            """
        )
        assert "REL002" not in rule_ids(findings)


class TestGOV001Tags:
    def test_untagged_flagged(self, run_rules):
        findings = run_rules('resource "aws_instance" "i" { instance_type = "t3.micro" }')
        assert "GOV001" in rule_ids(findings)

    def test_tagged_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_instance" "i" {
              instance_type = "t3.micro"
              tags = { Name = "i" }
            }
            """
        )
        assert "GOV001" not in rule_ids(findings)


class TestGOV002RequiredTags:
    def test_inactive_without_policy(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "i" { tags = { Name = "i" } }'
        )
        assert "GOV002" not in rule_ids(findings)

    def test_missing_required_tag_flagged(self, run_rules):
        findings = run_rules(
            'resource "aws_instance" "i" { tags = { Name = "i" } }',
            required_tags=("Owner", "CostCenter"),
        )
        match = [f for f in findings if f.rule_id == "GOV002"]
        assert match and "Owner" in match[0].message and "CostCenter" in match[0].message

    def test_all_required_tags_present_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_instance" "i" {
              tags = { Name = "i", Owner = "t", CostCenter = "42" }
            }
            """,
            required_tags=("Owner", "CostCenter"),
        )
        assert "GOV002" not in rule_ids(findings)


class TestCOST006UnattachedVolume:
    def test_unattached_volume_flagged_with_estimate(self, run_rules):
        findings = run_rules(
            'resource "aws_ebs_volume" "orphan" {\n'
            '  size = 200\n  type = "gp3"\n  encrypted = true\n'
            '  tags = { Name = "o" }\n}'
        )
        match = [f for f in findings if f.rule_id == "COST006"]
        assert match and match[0].monthly_cost == 16.0  # 200 GB x $0.08

    def test_attachment_suppresses(self, run_rules):
        findings = run_rules(
            """
            resource "aws_ebs_volume" "used" {
              size = 200
              type = "gp3"
              encrypted = true
              tags = { Name = "u" }
            }
            resource "aws_volume_attachment" "a" {
              device_name = "/dev/sdf"
              volume_id   = aws_ebs_volume.used.id
              instance_id = aws_instance.app.id
            }
            """
        )
        assert "COST006" not in {f.rule_id for f in findings}


class TestREL003DeletionProtection:
    def test_unprotected_db_flagged(self, run_rules):
        findings = run_rules('resource "aws_db_instance" "db" {}')
        assert "REL003" in {f.rule_id for f in findings}

    def test_protected_db_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { deletion_protection = true }'
        )
        assert "REL003" not in {f.rule_id for f in findings}
