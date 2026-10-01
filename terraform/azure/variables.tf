variable "subscription_id" {
  description = "Target subscription."
  type        = string
}

variable "location" {
  description = "Azure region. canadacentral (Toronto) keeps data in Canada."
  type        = string
  default     = "canadacentral"
}

variable "project" {
  type    = string
  default = "palisade"
}

variable "owner" {
  description = "Team or person accountable for these resources (required tag)."
  type        = string
}

variable "security_contact_email" {
  description = "Receives Defender for Cloud alerts."
  type        = string
}

variable "vnet_cidr" {
  type    = string
  default = "10.50.0.0/16"
}

variable "enable_defender" {
  description = "Defender for Cloud Standard plans (CIS 2.1). Off by default because they are billed; AZ-DEF-001 flags the subscription while false."
  type        = bool
  default     = false
}

variable "enable_event_subscription" {
  description = "Wire Event Grid to the function. Apply with false, publish the code (make publish-azure-function), then apply with true."
  type        = bool
  default     = false
}

variable "remediation_dry_run" {
  description = "When true the function logs intended fixes without applying them."
  type        = bool
  default     = true
}

variable "extra_tags" {
  type    = map(string)
  default = {}
}
