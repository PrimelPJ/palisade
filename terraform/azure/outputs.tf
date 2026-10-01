output "resource_group" {
  value = azurerm_resource_group.this.name
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.this.id
}

output "data_storage_account" {
  value = azurerm_storage_account.data.name
}

output "key_vault" {
  value = azurerm_key_vault.this.name
}

output "remediation_function" {
  value = azurerm_linux_function_app.remediator.name
}
