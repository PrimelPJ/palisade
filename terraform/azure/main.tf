terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.8"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  subscription_id = var.subscription_id
  # Shared keys are disabled on storage accounts, so Terraform must use Entra ID for data-plane calls.
  storage_use_azuread = true

  features {
    key_vault {
      # Purge protection is on; never let `terraform destroy` try to purge.
      purge_soft_delete_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }
}

data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

locals {
  name   = var.project
  suffix = random_string.suffix.result
  tags = merge(
    {
      project             = var.project
      owner               = var.owner
      data_classification = "internal"
      managed_by          = "terraform"
    },
    var.extra_tags,
  )
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}
