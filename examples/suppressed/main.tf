# Demonstrates inline suppressions: the SSH rule below is a deliberate,
# documented exception, so this scan reports zero findings and exits 0.
# The suppression and its reason still appear in the JSON report and the
# audit trail - exceptions are visible, never silent.

resource "aws_security_group" "bastion" {
  name        = "bastion-sg"
  description = "SSH bastion"

  ingress {
    # cairn:ignore SEC001 reason=bastion is reachable only through the corporate VPN route table
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "bastion-sg"
    Environment = "prod"
    Owner       = "platform"
  }
}
