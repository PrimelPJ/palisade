# Deliberately insecure configuration. tests/test_policies.py asserts every custom
# Checkov policy rejects it. Never deploy this.

resource "azurerm_resource_group" "untagged" {
  name     = "rg-insecure"
  location = "canadacentral"
}

resource "azurerm_storage_account" "weak" {
  name                            = "stinsecure"
  resource_group_name             = "rg-insecure"
  location                        = "canadacentral"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = true
  tags                            = { owner = "nobody" }
}

resource "aws_cloudtrail" "single_region" {
  name                       = "trail"
  s3_bucket_name             = "some-bucket"
  is_multi_region_trail      = false
  enable_log_file_validation = false
}

resource "aws_s3_bucket" "disposable" {
  bucket        = "insecure-bucket"
  force_destroy = true
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "azurerm_network_security_rule" "rdp" {
  name                        = "rdp-any"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-insecure"
  network_security_group_name = "nsg"
}
