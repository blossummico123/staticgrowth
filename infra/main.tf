# ---------------------------------------------------------------------------
# AI Sentinel — Azure Infrastructure (Terraform)
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "azurerm_client_config" "current" {}

locals {
  prefix = "${var.project_name}-${var.environment}"
  tags = {
    project     = "ai-sentinel"
    environment = var.environment
    managed_by  = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.prefix}"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------------------
# Log Analytics (required for Container Apps)
# ---------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "log-${local.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

# ---------------------------------------------------------------------------
# Container Registry (ACR)
# ---------------------------------------------------------------------------

resource "azurerm_container_registry" "acr" {
  name                = replace("acr${local.prefix}", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

# ---------------------------------------------------------------------------
# Managed Identity (for ACR pull + Key Vault access)
# ---------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "api_identity" {
  name                = "id-${local.prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.api_identity.principal_id
}

# ---------------------------------------------------------------------------
# Key Vault (secrets storage)
# ---------------------------------------------------------------------------

resource "azurerm_key_vault" "kv" {
  name                       = "kv-${local.prefix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  tags                       = local.tags

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "Set", "List", "Delete", "Purge"]
  }

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azurerm_user_assigned_identity.api_identity.principal_id
    secret_permissions = ["Get", "List"]
  }
}

resource "azurerm_key_vault_secret" "openai_key" {
  name         = "openai-api-key"
  value        = var.openai_api_key
  key_vault_id = azurerm_key_vault.kv.id
}

# ---------------------------------------------------------------------------
# Blob Storage (model file uploads)
# ---------------------------------------------------------------------------

resource "azurerm_storage_account" "storage" {
  name                     = replace("st${local.prefix}", "-", "")
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_storage_container" "uploads" {
  name                  = "model-uploads"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "results" {
  name                  = "scan-results"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "storage_blob" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.api_identity.principal_id
}

# ---------------------------------------------------------------------------
# Container App Environment
# ---------------------------------------------------------------------------

resource "azurerm_container_app_environment" "env" {
  name                       = "cae-${local.prefix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  tags                       = local.tags
}

# ---------------------------------------------------------------------------
# Container App (the API)
# ---------------------------------------------------------------------------

resource "azurerm_container_app" "api" {
  name                         = "ca-${local.prefix}"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.api_identity.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.api_identity.id
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = "ai-sentinel-api"
      image  = "${azurerm_container_registry.acr.login_server}/ai-sentinel-api:${var.container_image_tag}"
      cpu    = var.container_cpu
      memory = var.container_memory

      env {
        name        = "OPENAI_API_KEY"
        secret_name = "openai-api-key"
      }

      env {
        name  = "AZURE_STORAGE_ACCOUNT"
        value = azurerm_storage_account.storage.name
      }

      env {
        name  = "AZURE_STORAGE_CONTAINER_UPLOADS"
        value = "model-uploads"
      }

      env {
        name  = "AZURE_STORAGE_CONTAINER_RESULTS"
        value = "scan-results"
      }

      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.api_identity.client_id
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/api/v1/health"
        port      = 8000
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/api/v1/health"
        port      = 8000
      }
    }
  }

  secret {
    name  = "openai-api-key"
    value = var.openai_api_key
  }

  ingress {
    external_enabled = true
    target_port      = 8000

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}
