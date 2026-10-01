variable "region" {
  description = "Primary region. ca-central-1 keeps data in Canada."
  type        = string
  default     = "ca-central-1"
}

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "palisade"
}

variable "owner" {
  description = "Team or person accountable for these resources (required tag)."
  type        = string
}

variable "alert_email" {
  description = "Email subscribed to security alerts. Leave empty to skip the subscription."
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "remediation_dry_run" {
  description = "When true the Lambda reports what it would fix without changing anything."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "How long CloudTrail and flow logs are kept before expiring."
  type        = number
  default     = 365
}

variable "extra_tags" {
  type    = map(string)
  default = {}
}
