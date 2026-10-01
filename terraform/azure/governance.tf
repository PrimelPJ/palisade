# Logging, threat protection and preventive policy (CIS Azure 2.x, 5.1).

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.name}-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 365
  daily_quota_gb      = 1 # cap spend while learning; raise for production
  tags                = local.tags
}

# Export the subscription activity log (who changed what, CIS 5.1.1).
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "${local.name}-activity-log"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  dynamic "enabled_log" {
    for_each = ["Administrative", "Security", "Policy", "Alert", "ServiceHealth", "Recommendation", "ResourceHealth"]
    content {
      category = enabled_log.value
    }
  }
}

# ---- Defender for Cloud ----------------------------------------------------------------

locals {
  defender_plans = var.enable_defender ? toset(["VirtualMachines", "StorageAccounts", "KeyVaults", "SqlServers", "Arm"]) : toset([])
}

resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each      = local.defender_plans
  tier          = "Standard"
  resource_type = each.value
  subplan       = each.value == "StorageAccounts" ? "DefenderForStorageV2" : null
}

resource "azurerm_security_center_contact" "this" {
  #checkov:skip=CKV_AZURE_20:Email is the alert channel; no on-call phone for a personal subscription.
  name                = "default"
  email               = var.security_contact_email
  alert_notifications = true
  alerts_to_admins    = true
}

# ---- Azure Policy: prevent, then audit ---------------------------------------------------

# Preventive guardrail: storage accounts that allow anonymous blob access are rejected at
# deploy time, so this class of finding cannot be created in the first place.
resource "azurerm_policy_definition" "deny_public_blob" {
  name         = "${local.name}-deny-public-blob"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Palisade: deny storage accounts that allow anonymous blob access"

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        {
          anyOf = [
            { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", exists = false },
            { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", equals = true },
          ]
        },
      ]
    }
    "then" = { effect = "[parameters('effect')]" }
  })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })
}

resource "azurerm_subscription_policy_assignment" "deny_public_blob" {
  name                 = "${local.name}-deny-public-blob"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_definition.deny_public_blob.id
  display_name         = azurerm_policy_definition.deny_public_blob.display_name
}

# Required tags, so every resource has an accountable owner.
data "azurerm_policy_definition" "require_tag_rg" {
  display_name = "Require a tag on resource groups"
}

resource "azurerm_subscription_policy_assignment" "require_owner_tag" {
  name                 = "${local.name}-require-owner-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag_rg.id
  display_name         = "Palisade: resource groups must have an owner tag"
  parameters           = jsonencode({ tagName = { value = "owner" } })
}

# Continuous compliance view against the full CIS benchmark (audit only).
data "azurerm_policy_set_definition" "cis" {
  display_name = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
}

resource "azurerm_subscription_policy_assignment" "cis" {
  name                 = "${local.name}-cis-v2"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_set_definition.cis.id
  display_name         = "CIS Azure Foundations v2.0.0 (audit)"
}
