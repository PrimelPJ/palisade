# Account-wide guardrails (CIS AWS 1.8, 2.1.4, 2.2.1) and threat detection.

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Single-account landing zone; no AWS Organization to delegate GuardDuty admin to.
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.this.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# IAM Access Analyzer flags resources shared outside the account.
resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${local.name}-account"
  type          = "ACCOUNT"
}
