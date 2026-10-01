output "cloudtrail_arn" {
  value = aws_cloudtrail.this.arn
}

output "audit_log_bucket" {
  value = aws_s3_bucket.logs.id
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "remediator_function" {
  value = aws_lambda_function.remediator.function_name
}

output "vpc_id" {
  value = aws_vpc.this.id
}
