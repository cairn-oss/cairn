"""Positive + negative behavioral tests for every SEC rule."""

from cairn.findings import Severity

from .conftest import rule_ids


class TestSEC001OpenIngress:
    def test_ssh_open_to_world_is_critical(self, run_rules):
        findings = run_rules(
            """
            resource "aws_security_group" "sg" {
              ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """
        )
        sec = [f for f in findings if f.rule_id == "SEC001"]
        assert len(sec) == 1
        assert sec[0].severity is Severity.CRITICAL

    def test_https_open_to_world_is_high(self, run_rules):
        findings = run_rules(
            """
            resource "aws_security_group" "sg" {
              ingress {
                from_port   = 443
                to_port     = 443
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """
        )
        sec = [f for f in findings if f.rule_id == "SEC001"]
        assert sec[0].severity is Severity.HIGH

    def test_all_protocols_open_is_critical(self, run_rules):
        findings = run_rules(
            """
            resource "aws_security_group" "sg" {
              ingress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """
        )
        assert any(
            f.rule_id == "SEC001" and f.severity is Severity.CRITICAL for f in findings
        )

    def test_ipv6_open_is_flagged(self, run_rules):
        findings = run_rules(
            """
            resource "aws_security_group" "sg" {
              ingress {
                from_port        = 80
                to_port          = 80
                protocol         = "tcp"
                ipv6_cidr_blocks = ["::/0"]
              }
            }
            """
        )
        assert "SEC001" in rule_ids(findings)

    def test_standalone_rule_resource(self, run_rules):
        findings = run_rules(
            """
            resource "aws_security_group_rule" "open" {
              type        = "ingress"
              from_port   = 3389
              to_port     = 3389
              protocol    = "tcp"
              cidr_blocks = ["0.0.0.0/0"]
            }
            """
        )
        assert any(
            f.rule_id == "SEC001" and f.severity is Severity.CRITICAL for f in findings
        )

    def test_private_cidr_is_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_security_group" "sg" {
              ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["10.0.0.0/8"]
              }
            }
            """
        )
        assert "SEC001" not in rule_ids(findings)


class TestSEC002S3Encryption:
    def test_bucket_without_encryption_flagged(self, run_rules):
        findings = run_rules('resource "aws_s3_bucket" "b" { bucket = "x" }')
        assert "SEC002" in rule_ids(findings)

    def test_companion_resource_suppresses(self, run_rules):
        findings = run_rules(
            """
            resource "aws_s3_bucket" "b" { bucket = "x" }
            resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
              bucket = aws_s3_bucket.b.id
            }
            """
        )
        assert "SEC002" not in rule_ids(findings)

    def test_inline_block_suppresses(self, run_rules):
        findings = run_rules(
            """
            resource "aws_s3_bucket" "b" {
              server_side_encryption_configuration {
                rule {
                  apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
                }
              }
            }
            """
        )
        assert "SEC002" not in rule_ids(findings)


class TestSEC003PublicACL:
    def test_public_read_write_is_critical(self, run_rules):
        findings = run_rules(
            'resource "aws_s3_bucket" "b" { acl = "public-read-write" }'
        )
        match = [f for f in findings if f.rule_id == "SEC003"]
        assert match and match[0].severity is Severity.CRITICAL

    def test_private_acl_is_clean(self, run_rules):
        findings = run_rules('resource "aws_s3_bucket" "b" { acl = "private" }')
        assert "SEC003" not in rule_ids(findings)


class TestSEC004SEC005RDS:
    def test_public_and_unencrypted_db(self, run_rules):
        findings = run_rules(
            """
            resource "aws_db_instance" "db" {
              publicly_accessible = true
            }
            """
        )
        ids = rule_ids(findings)
        assert "SEC004" in ids and "SEC005" in ids

    def test_private_encrypted_db_is_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_db_instance" "db" {
              publicly_accessible     = false
              storage_encrypted       = true
              backup_retention_period = 7
              deletion_protection     = true
              tags = { Name = "db" }
            }
            """
        )
        assert rule_ids(findings) == set()


class TestSEC006EBS:
    def test_unencrypted_volume(self, run_rules):
        findings = run_rules(
            'resource "aws_ebs_volume" "v" { size = 10\n availability_zone = "us-east-1a" }'
        )
        assert "SEC006" in rule_ids(findings)

    def test_encrypted_volume_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_ebs_volume" "v" {
              size      = 10
              encrypted = true
              tags      = { Name = "v" }
            }
            """
        )
        assert "SEC006" not in rule_ids(findings)


class TestSEC007IAMWildcard:
    def test_star_on_star_json(self, run_rules):
        findings = run_rules(
            """
            resource "aws_iam_policy" "p" {
              policy = <<EOF
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            EOF
            }
            """
        )
        assert "SEC007" in rule_ids(findings)

    def test_scoped_policy_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_iam_policy" "p" {
              policy = <<EOF
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::b/*"}]}
            EOF
            }
            """
        )
        assert "SEC007" not in rule_ids(findings)

    def test_deny_star_is_not_flagged(self, run_rules):
        findings = run_rules(
            """
            resource "aws_iam_policy" "p" {
              policy = <<EOF
            {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
            EOF
            }
            """
        )
        assert "SEC007" not in rule_ids(findings)


class TestSEC008Secrets:
    def test_literal_password_flagged(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { password = "hunter2" }'
        )
        assert "SEC008" in rule_ids(findings)

    def test_variable_reference_is_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_db_instance" "db" { password = var.db_password }'
        )
        assert "SEC008" not in rule_ids(findings)


class TestSEC009IMDSv2:
    def test_missing_metadata_options(self, run_rules):
        findings = run_rules('resource "aws_instance" "i" { instance_type = "t3.micro" }')
        assert "SEC009" in rule_ids(findings)

    def test_tokens_required_is_clean(self, run_rules):
        findings = run_rules(
            """
            resource "aws_instance" "i" {
              instance_type = "t3.micro"
              metadata_options { http_tokens = "required" }
              tags = { Name = "i" }
            }
            """
        )
        assert "SEC009" not in rule_ids(findings)


class TestSEC010PlaintextListener:
    def test_http_forward_listener_flagged(self, run_rules):
        findings = run_rules(
            """
            resource "aws_lb_listener" "front" {
              port     = 80
              protocol = "HTTP"
              default_action {
                type = "forward"
              }
            }
            """
        )
        assert "SEC010" in {f.rule_id for f in findings}

    def test_http_redirect_listener_is_the_correct_pattern(self, run_rules):
        findings = run_rules(
            """
            resource "aws_lb_listener" "redirect" {
              port     = 80
              protocol = "HTTP"
              default_action {
                type = "redirect"
              }
            }
            """
        )
        assert "SEC010" not in {f.rule_id for f in findings}

    def test_https_listener_clean(self, run_rules):
        findings = run_rules(
            'resource "aws_lb_listener" "tls" { port = 443\n protocol = "HTTPS" }'
        )
        assert "SEC010" not in {f.rule_id for f in findings}
