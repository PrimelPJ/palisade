# Event-driven remediation: CloudTrail -> EventBridge -> Lambda -> SNS.
# Build the package first: `make package-lambda` (creates build/lambda).

locals {
  monitored_events = {
    "aws.s3" = [
      "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock",
      "DeleteBucketPublicAccessBlock", "PutBucketVersioning", "CreateBucket",
      # Account-level Block Public Access (logged under the S3 event source).
      "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock",
      "PutPublicAccessBlock", "DeletePublicAccessBlock",
    ]
    "aws.ec2" = [
      "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "ModifySecurityGroupRules",
      "CreateSecurityGroup", "DisableEbsEncryptionByDefault",
    ]
    "aws.cloudtrail" = ["StopLogging", "DeleteTrail", "UpdateTrail"]
    "aws.kms"        = ["DisableKeyRotation"]
  }
  # IAM is a global service: its CloudTrail events are only delivered to us-east-1.
  iam_events = [
    "CreateUser", "CreateLoginProfile", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
    "AttachRolePolicy", "PutRolePolicy", "UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy",
  ]
  lambda_name = "${local.name}-remediator"
}

# ---- Alerts ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.logs.id
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.lambda_name}-dlq"
  kms_master_key_id         = aws_kms_key.logs.id
  message_retention_seconds = 1209600
}

# ---- Least-privilege role --------------------------------------------------------------

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "remediator" {
  name               = local.lambda_name
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

data "aws_iam_policy_document" "remediator" {
  #checkov:skip=CKV_AWS_356:Describe/List/Get actions and account-level settings do not support resource scoping.
  #checkov:skip=CKV_AWS_111:Write actions are scoped by ARN pattern below where the service allows it.
  #checkov:skip=CKV_AWS_109:Bucket policy/ACL writes are how public exposure gets removed; a Deny statement blocks loosening.
  statement {
    sid = "ReadPosture"
    actions = [
      "sts:GetCallerIdentity",
      "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy", "iam:ListUsers", "iam:ListRoles",
      "iam:GetLoginProfile", "iam:ListMFADevices", "iam:ListAccessKeys",
      "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:GetUserPolicy",
      "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy",
      "s3:ListAllMyBuckets", "s3:GetAccountPublicAccessBlock", "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration",
      "ec2:DescribeSecurityGroups", "ec2:GetEbsEncryptionByDefault",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus",
    ]
    resources = ["*"]
  }

  statement {
    sid = "FixBuckets"
    actions = [
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl",
      "s3:PutBucketVersioning",
    ]
    resources = ["arn:${local.partition}:s3:::*"]
  }

  statement {
    sid       = "FixSecurityGroups"
    actions   = ["ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress"]
    resources = ["arn:${local.partition}:ec2:*:${local.account_id}:security-group/*"]
  }

  statement {
    sid       = "FixTrails"
    actions   = ["cloudtrail:StartLogging", "cloudtrail:UpdateTrail"]
    resources = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
  }

  statement {
    sid       = "FixKeys"
    actions   = ["kms:EnableKeyRotation"]
    resources = ["arn:${local.partition}:kms:*:${local.account_id}:key/*"]
  }

  statement {
    sid       = "FixAccountSettings"
    actions   = ["ec2:EnableEbsEncryptionByDefault", "iam:UpdateAccountPasswordPolicy"]
    resources = ["*"] # account-level settings have no resource ARN
  }

  # Fixes may never weaken anything, even if the code had a bug.
  statement {
    sid    = "NeverLoosen"
    effect = "Deny"
    actions = [
      "s3:PutAccountPublicAccessBlock", "s3:DeleteBucket",
      "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
      "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
      "kms:DisableKeyRotation", "kms:ScheduleKeyDeletion",
      "iam:Create*", "iam:Delete*", "iam:Attach*", "iam:Detach*", "iam:Put*",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Alert"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  statement {
    sid       = "UseLogsKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.logs.arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.remediator.arn}:*"]
  }

  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediator" {
  name   = "remediate"
  role   = aws_iam_role.remediator.id
  policy = data.aws_iam_policy_document.remediator.json
}

# ---- Function ---------------------------------------------------------------------------

data "archive_file" "remediator" {
  type        = "zip"
  source_dir  = "${path.module}/../../build/lambda"
  output_path = "${path.module}/../../build/remediator.zip"
}

resource "aws_cloudwatch_log_group" "remediator" {
  name              = "/aws/lambda/${local.lambda_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_lambda_function" "remediator" {
  #checkov:skip=CKV_AWS_117:Only calls AWS control-plane APIs; a VPC would add NAT cost with no isolation gain.
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer profile; add for production.
  function_name                  = local.lambda_name
  role                           = aws_iam_role.remediator.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 120
  memory_size                    = 256
  filename                       = data.archive_file.remediator.output_path
  source_code_hash               = data.archive_file.remediator.output_base64sha256
  reserved_concurrent_executions = 5
  kms_key_arn                    = aws_kms_key.logs.arn

  environment {
    variables = {
      PALISADE_ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      PALISADE_DRY_RUN         = tostring(var.remediation_dry_run)
      PALISADE_SELF_ROLE_NAME  = aws_iam_role.remediator.name
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.remediator, aws_iam_role_policy.remediator]
}

# ---- Triggers (primary region) ----------------------------------------------------------

resource "aws_cloudwatch_event_rule" "risky_api_calls" {
  name        = "${local.name}-risky-api-calls"
  description = "Configuration changes that can break a Palisade rule"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    source        = keys(local.monitored_events)
    detail = {
      eventName = distinct(flatten(values(local.monitored_events)))
    }
  })
}

resource "aws_cloudwatch_event_target" "remediator" {
  rule = aws_cloudwatch_event_rule.risky_api_calls.name
  arn  = aws_lambda_function.remediator.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.risky_api_calls.arn
}

resource "aws_cloudwatch_event_rule" "iam_changes_local" {
  name        = "${local.name}-iam-changes"
  description = "IAM changes forwarded from us-east-1"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    source        = ["aws.iam"]
    detail        = { eventName = local.iam_events }
  })
}

resource "aws_cloudwatch_event_target" "iam_remediator" {
  rule = aws_cloudwatch_event_rule.iam_changes_local.name
  arn  = aws_lambda_function.remediator.arn
}

resource "aws_lambda_permission" "iam_events" {
  statement_id  = "AllowEventBridgeIam"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_changes_local.arn
}

# ---- Forward global IAM events from us-east-1 --------------------------------------------

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.tags
  }
}

data "aws_iam_policy_document" "assume_events" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "forward_iam_events" {
  name               = "${local.name}-forward-iam-events"
  assume_role_policy = data.aws_iam_policy_document.assume_events.json
}

resource "aws_iam_role_policy" "forward_iam_events" {
  role = aws_iam_role.forward_iam_events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = "arn:${local.partition}:events:${var.region}:${local.account_id}:event-bus/default"
    }]
  })
}

resource "aws_cloudwatch_event_rule" "iam_changes_global" {
  provider    = aws.us_east_1
  name        = "${local.name}-iam-changes-forward"
  description = "Forward IAM API calls to the Palisade region"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    source        = ["aws.iam"]
    detail        = { eventName = local.iam_events }
  })
}

resource "aws_cloudwatch_event_target" "forward" {
  count    = var.region == "us-east-1" ? 0 : 1
  provider = aws.us_east_1
  rule     = aws_cloudwatch_event_rule.iam_changes_global.name
  arn      = "arn:${local.partition}:events:${var.region}:${local.account_id}:event-bus/default"
  role_arn = aws_iam_role.forward_iam_events.arn
}
