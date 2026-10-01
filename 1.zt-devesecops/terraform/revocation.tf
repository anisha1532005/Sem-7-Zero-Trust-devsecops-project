resource "aws_iam_policy" "revocation_policy" {
  name        = "ZT-DevSecOps-Revocation"
  description = "Explicit deny policy used to revoke deployment access"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "RevokeDeploymentAccess"
        Effect = "Deny"

        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.deployment_bucket.arn}/*"
      }
    ]
  })
}

output "revocation_policy_arn" {
  value = aws_iam_policy.revocation_policy.arn
}