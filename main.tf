#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: MIT-0

data "aws_region" "current" {}

data "aws_organizations_organization" "org" {}

#Get user identity
data "aws_caller_identity" "current" {}

locals {
    account_id = data.aws_caller_identity.current.account_id
}

locals {
  ou_arn = "arn:aws:organizations::${data.aws_caller_identity.current.account_id}:ou/${data.aws_organizations_organization.org.id}/${var.ou}"
    }

# Create a SNS topic for root access keys
resource "aws_sns_topic" "root_access_key_created" {
  name = "root-access-key-alert"
  kms_master_key_id = "alias/rootalertsSNS"
}

# Create a SNS topic for root login
resource "aws_sns_topic" "root_login" {
  name = "root-login-alert"
  kms_master_key_id = "alias/rootalertsSNS"
  
}

# Create Customer Managed Key for encrypting the SNS topic at rest
resource "aws_kms_key" "sns_key" {
  description             = "Key for Root Alerts SNS"
  deletion_window_in_days = 7
  policy = data.aws_iam_policy_document.sns-policy.json
  enable_key_rotation = true
}

# Create key alias
resource "aws_kms_alias" "sns_key" {
  name          = "alias/rootalertsSNS"
  target_key_id = aws_kms_key.sns_key.key_id
}

# Create key policy 
data "aws_iam_policy_document" "sns-policy" {
  statement {
    sid       = "allow_events_to_decrypt_key"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
  }

# Default KMS key policy (https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

# Email addresses which will get alerts for root access key usage
resource "aws_sns_topic_subscription" "root_access_key_subscription" {

  count = length(var.emails)
  topic_arn = aws_sns_topic.root_access_key_created.arn
  protocol  = "email"
  endpoint = var.emails[count.index]

}

# Email addresses which will get alerts for root usage
resource "aws_sns_topic_subscription" "root_login_subscription" {
  count = length(var.emails)
  topic_arn = aws_sns_topic.root_login.arn #aws_sns_topic.sns_topic.arn
  protocol  = "email"
  endpoint = var.emails[count.index]
}

# Create a CloudWatch Logs metric filter for root access keys
resource "aws_cloudwatch_log_metric_filter" "rootaccesskey_filter" {
  name           = "RootAccessKeyUsage"
  pattern        = "{$.userIdentity.type = \"Root\" && $.eventName = \"CreateAccessKey\"}"
  log_group_name = var.ct_log_group
  metric_transformation {
    name      = "RootAccessKeyUsage"
    namespace = "RootAccessKeyUsage"
    value     = "1"
  }
}

# Create a CloudWatch Logs metric filter for root login
resource "aws_cloudwatch_log_metric_filter" "rootlogin_filter" {
  name           = "RootLoginUsage"
  pattern        = "{$.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AWsServiceEvent\"}"
  log_group_name = var.ct_log_group
   metric_transformation {
    name      = "RootLoginUsage"
    namespace = "RootLoginUsage"
    value     = "1"
  }
}

# Create a CloudWatch Logs metric alarm to for root access keys usage
resource "aws_cloudwatch_metric_alarm" "root_accesskeys_alarm" {
  alarm_name          = "root-access-key-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccessKeyUsage"
  namespace           = "RootAccessKeyUsage"
  period              = "10" #increase the threshold to 10 mins
  statistic           = "Sum"
  threshold           = "1"

  alarm_actions = [
    aws_sns_topic.root_access_key_created.arn,
  ]
}

# Create a CloudWatch Logs metric alarm to for root login
resource "aws_cloudwatch_metric_alarm" "root_login_alarm" {
  alarm_name          = "root-login"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootLoginUsage"
  namespace           = "RootLoginUsage"
  period              = "10"
  statistic           = "Sum"
  threshold           = "1"

  alarm_actions = [
    aws_sns_topic.root_login.arn,
  ]
}

#Control Tower control to restrict root (https://docs.aws.amazon.com/controltower/latest/userguide/strongly-recommended-controls.html#disallow-root-auser-actions)
resource "aws_controltower_control" "root" {
  control_identifier = "arn:aws:controltower:${data.aws_region.current.name}::control/AWS-GR_RESTRICT_ROOT_USER"
  target_identifier = local.ou_arn
}

#Control Tower control to disallow creation of root access keys  (https://docs.aws.amazon.com/controltower/latest/userguide/strongly-recommended-controls.html#disallow-root-access-keys)
resource "aws_controltower_control" "rootaccesskeys" {
  control_identifier = "arn:aws:controltower:${data.aws_region.current.name}::control/AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS"
  target_identifier = local.ou_arn
}