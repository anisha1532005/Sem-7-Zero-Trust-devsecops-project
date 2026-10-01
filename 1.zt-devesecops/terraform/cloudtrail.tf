resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.deployment_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = "s3:GetBucketAcl"

        Resource = aws_s3_bucket.deployment_bucket.arn

        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:ap-south-1:904290465920:trail/ZT-DevSecOps-Trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "${aws_s3_bucket.deployment_bucket.arn}/AWSLogs/904290465920/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:ap-south-1:904290465920:trail/ZT-DevSecOps-Trail"
          }
        }
      }
    ]
  })
}


resource "aws_cloudtrail" "zero_trust_trail" {
  name                          = "ZT-DevSecOps-Trail"
  s3_bucket_name                = aws_s3_bucket.deployment_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Project = "Zero-Trust-DevSecOps"
    Purpose = "Security Monitoring"
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_bucket_policy
  ]
}