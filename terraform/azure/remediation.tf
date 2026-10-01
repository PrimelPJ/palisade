# Event-driven remediation: ARM write -> Event Grid -> Function -> fix.
# Publish code with `make publish-azure-function`, then set enable_event_subscription = true.

locals {
  function_name = "func-${local.name}-${local.suffix}"
  watched_operations = [
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.KeyVault/vaults/write",
  ]
}

# A user-assigned identity lets the function recognise (and ignore) events caused by its own fixes.
resource "azurerm_user_assigned_identity" "remediator" {
  name                = "id-${local.name}-remediator"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

# Exactly the actions the fixes need; no generic Contributor.
resource "azurerm_role_definition" "remediator" {
  name        = "${local.name}-remediator"
  scope       = data.azurerm_subscription.current.id
  description = "Read posture and apply Palisade's auto-safe fixes."

  permissions {
    actions = [
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/write",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkSecurityGroups/securityRules/read",
      "Microsoft.Network/networkSecurityGroups/securityRules/delete",
      "Microsoft.KeyVault/vaults/read",
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.current.id]
}

resource "azurerm_role_assignment" "remediator" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = azurerm_role_definition.remediator.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.remediator.principal_id
}

# Functions runtime state. Kept separate from the data account so its looser needs
# (shared key for the runtime) never touch business data.
resource "azurerm_storage_account" "function" {
  #checkov:skip=CKV_AZURE_33:Runtime-only account, no queues with business data.
  #checkov:skip=CKV_AZURE_206:Runtime state is disposable; LRS is sufficient.
  #checkov:skip=CKV2_AZURE_1:Runtime-only account; Microsoft-managed keys are acceptable.
  #checkov:skip=CKV2_AZURE_33:Consumption plan cannot reach a private endpoint.
  #checkov:skip=CKV_AZURE_59:Consumption plan requires public reachability of its runtime storage.
  #checkov:skip=CKV2_AZURE_40:The Functions consumption runtime authenticates with the account key.
  #checkov:skip=CKV2_AZURE_41:No SAS tokens are issued from this account.
  name                            = "stfn${local.name}${local.suffix}"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  tags                            = local.tags

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_application_insights" "this" {
  name                = "appi-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  workspace_id        = azurerm_log_analytics_workspace.this.id
  application_type    = "other"
  tags                = local.tags
}

resource "azurerm_service_plan" "this" {
  #checkov:skip=CKV_AZURE_225:Consumption (Y1) plans do not support zone redundancy.
  #checkov:skip=CKV_AZURE_212:Consumption plans scale on demand; minimum instance count does not apply.
  name                = "asp-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.tags
}

resource "azurerm_linux_function_app" "remediator" {
  #checkov:skip=CKV_AZURE_221:Event Grid delivers over the public endpoint on the consumption plan.
  name                       = local.function_name
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  service_plan_id            = azurerm_service_plan.this.id
  storage_account_name       = azurerm_storage_account.function.name
  storage_account_access_key = azurerm_storage_account.function.primary_access_key
  https_only                 = true
  tags                       = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediator.id]
  }

  site_config {
    minimum_tls_version      = "1.2"
    ftps_state               = "Disabled"
    http2_enabled            = true
    application_insights_key = azurerm_application_insights.this.instrumentation_key
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    AZURE_CLIENT_ID         = azurerm_user_assigned_identity.remediator.client_id
    PALISADE_SELF_CLIENT_ID = azurerm_user_assigned_identity.remediator.client_id
    PALISADE_DRY_RUN        = tostring(var.remediation_dry_run)
  }
}

resource "azurerm_eventgrid_system_topic" "subscription" {
  name                = "evgt-${local.name}-subscription"
  resource_group_name = azurerm_resource_group.this.name
  location            = "global"
  source_resource_id  = data.azurerm_subscription.current.id
  topic_type          = "Microsoft.Resources.Subscriptions"
  tags                = local.tags
}

resource "azurerm_eventgrid_system_topic_event_subscription" "remediate" {
  count               = var.enable_event_subscription ? 1 : 0
  name                = "palisade-remediate"
  system_topic        = azurerm_eventgrid_system_topic.subscription.name
  resource_group_name = azurerm_resource_group.this.name

  included_event_types = ["Microsoft.Resources.ResourceWriteSuccess"]

  azure_function_endpoint {
    function_id                       = "${azurerm_linux_function_app.remediator.id}/functions/palisade_remediate"
    max_events_per_batch              = 1
    preferred_batch_size_in_kilobytes = 64
  }

  advanced_filter {
    string_in {
      key    = "data.operationName"
      values = local.watched_operations
    }
  }

  retry_policy {
    max_delivery_attempts = 10
    event_time_to_live    = 60
  }
}
