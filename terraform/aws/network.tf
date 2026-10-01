# Network baseline: private-by-default VPC, flow logs, locked-down default SG (CIS AWS 3.9, 5.2, 5.4).

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only the first two zones are used, so new zones cannot change the result.
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.name}-vpc" }
}

resource "aws_default_security_group" "this" {
  # Declaring it with no rules strips the default allow-all-from-self and egress rules.
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.name}-default-locked" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${local.name}-private-${count.index}", tier = "private" }
}

resource "aws_flow_log" "this" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.logs.arn}/vpc-flow-logs"

  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_security_group" "web" {
  #checkov:skip=CKV2_AWS_5:Baseline security group for workloads deployed later (load balancers, ECS services).
  name        = "${local.name}-web"
  description = "Web tier: HTTPS in, HTTPS out. Admin access is via SSM Session Manager, never SSH."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${local.name}-web" }
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  #checkov:skip=CKV_AWS_260:Public HTTPS is the purpose of the web tier.
  security_group_id = aws_security_group.web.id
  description       = "HTTPS from the internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "web_https_out" {
  security_group_id = aws_security_group.web.id
  description       = "HTTPS to AWS APIs and dependencies"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}
