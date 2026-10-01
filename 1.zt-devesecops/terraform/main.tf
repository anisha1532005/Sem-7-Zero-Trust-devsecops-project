terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "deployment_bucket" {
  bucket_prefix = "zt-devsecops-"

  tags = {
    Project = "Zero-Trust-DevSecOps"
    Purpose = "Secure Deployment"
  }
}

resource "aws_s3_bucket_public_access_block" "deployment_bucket" {
  bucket = aws_s3_bucket.deployment_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "bucket_name" {
  value = aws_s3_bucket.deployment_bucket.bucket
}