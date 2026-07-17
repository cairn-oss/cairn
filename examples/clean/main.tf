# A well-configured counterpart: Cairn should report zero findings here.
# Used as the false-positive regression fixture.

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web tier"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    Name        = "web-sg"
    Environment = "prod"
    Owner       = "platform"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-prod-logs"

  tags = {
    Name        = "acme-prod-logs"
    Environment = "prod"
    Owner       = "platform"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name        = "app-server"
    Environment = "prod"
    Owner       = "platform"
  }
}

resource "aws_db_instance" "main" {
  identifier              = "prod-db"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  publicly_accessible     = false
  storage_encrypted       = true
  backup_retention_period = 14
  deletion_protection     = true
  password                = var.db_password

  tags = {
    Name        = "prod-db"
    Environment = "prod"
    Owner       = "platform"
  }
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
  encrypted         = true

  tags = {
    Name        = "app-data"
    Environment = "prod"
    Owner       = "platform"
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.app.id
}

resource "aws_lb_listener" "redirect" {
  load_balancer_arn = aws_lb.front.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
