# Deliberately problematic Terraform used in Cairn's demo and e2e tests.
# Every resource below plants at least one issue; see examples/README.md.

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web tier"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SEC001 (CRITICAL: SSH to the world)
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SEC001 (HIGH: 443 open — often intended, still flagged)
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-prod-logs"
  # SEC002: no encryption · REL002: no versioning · GOV001: no tags
}

resource "aws_instance" "batch" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "m5.4xlarge" # COST001: ~$560/mo, likely oversized
  # SEC009: no metadata_options (IMDSv1 allowed) · GOV001: no tags
}

resource "aws_instance" "legacy" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t2.large" # COST005: previous generation

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name        = "legacy-worker"
    Environment = "prod"
  }
}

resource "aws_db_instance" "main" {
  identifier              = "prod-db"
  engine                  = "postgres"
  instance_class          = "db.r5.4xlarge" # COST004: very large
  publicly_accessible     = true            # SEC004 (CRITICAL)
  backup_retention_period = 0               # REL001: no backups
  password                = "hunter2-prod!" # SEC008 (CRITICAL: hardcoded secret)
  # SEC005: storage_encrypted unset · GOV001: no tags
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 500
  type              = "gp2" # COST002: gp3 is cheaper
  # SEC006: unencrypted · GOV001: no tags
}

resource "aws_eip" "spare" {
  # COST003: allocated but associated with nothing
}

resource "aws_iam_policy" "admin" {
  name = "service-policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
  # SEC007 (CRITICAL: * on *)
}

resource "aws_lb_listener" "front" {
  load_balancer_arn = aws_lb.front.arn
  port              = 80
  protocol          = "HTTP" # SEC010: plaintext, no redirect

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
