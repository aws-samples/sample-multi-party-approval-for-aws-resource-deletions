# Sample workload used to demonstrate the DeletionGuard Terraform path.
#
# 1. Deploy it with your normal pipeline/credentials:   terraform init && terraform apply
# 2. Try to destroy it the usual way:                    terraform destroy
#    -> fails with an explicit deny from the DeletionGuard-DenyDestructiveActions SCP
# 3. Request an approved destroy:  ../../scripts/request-terraform-change.ps1 -Operation destroy ...

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "deletion-guard-sample"
      ManagedBy = "terraform"
    }
  }
}

variable "region" {
  description = "Region for the sample resources (must be one of the guard's allowedTargetRegions)."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "deletion-guard-sample"
}

data "aws_caller_identity" "current" {}

# Customer managed key for the sample data. kms:ScheduleKeyDeletion is protected by
# DeletionGuard, so the approved destroy also covers this key (7-day waiting period).
resource "aws_kms_key" "sample" {
  description             = "${var.name_prefix} data encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "sample" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.sample.key_id
}

resource "aws_dynamodb_table" "orders" {
  name                        = "${var.name_prefix}-orders"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "orderId"
  deletion_protection_enabled = false

  attribute {
    name = "orderId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.sample.arn
  }
}

resource "aws_sqs_queue" "events" {
  name                              = "${var.name_prefix}-events"
  kms_master_key_id                 = aws_kms_key.sample.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_s3_bucket" "reports" {
  bucket        = "${var.name_prefix}-reports-${data.aws_caller_identity.current.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "table_name" {
  value = aws_dynamodb_table.orders.name
}

output "queue_url" {
  value = aws_sqs_queue.events.url
}

output "bucket_name" {
  value = aws_s3_bucket.reports.bucket
}
