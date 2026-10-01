resource "aws_iam_policy" "deployment_policy" {
  name        = "ZT-DevSecOps-S3-Deployment"
  description = "Least-privilege S3 access for the DevSecOps deployment"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.deployment_bucket.arn}/*"
      }
    ]
  })
}

output "deployment_policy_arn" {
  value = aws_iam_policy.deployment_policy.arn
}