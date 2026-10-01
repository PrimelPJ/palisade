terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Configure remote state before using this for real, e.g.:
  # backend "s3" {
  #   bucket         = "my-tf-state"
  #   key            = "palisade/aws.tfstate"
  #   region         = "ca-central-1"
  #   dynamodb_table = "tf-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  name       = var.project

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
