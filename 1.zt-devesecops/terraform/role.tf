data "aws_caller_identity" "current" {}

resource "aws_iam_role" "zero_trust_deploy_role" {
  name = "ZT-DevSecOps-Deploy-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  max_session_duration = 3600

  tags = {
    Project = "Zero-Trust-DevSecOps"
  }
}

resource "aws_iam_role_policy_attachment" "deployment_policy_attachment" {
  role       = aws_iam_role.zero_trust_deploy_role.name
  policy_arn = aws_iam_policy.deployment_policy.arn
}

output "zero_trust_role_arn" {
  value = aws_iam_role.zero_trust_deploy_role.arn
}