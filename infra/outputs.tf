output "api_url" {
  description = "Public URL of the AI Sentinel API"
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "acr_login_server" {
  description = "Azure Container Registry login server"
  value       = azurerm_container_registry.acr.login_server
}

output "resource_group_name" {
  description = "Resource group name"
  value       = azurerm_resource_group.main.name
}

output "storage_account_name" {
  description = "Blob storage account name"
  value       = azurerm_storage_account.storage.name
}

output "key_vault_name" {
  description = "Key Vault name"
  value       = azurerm_key_vault.kv.name
}

output "swagger_ui_url" {
  description = "Swagger UI for API documentation"
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}/docs"
}
