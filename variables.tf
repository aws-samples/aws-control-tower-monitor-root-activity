#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: MIT-0

variable "ct_log_group" {
  description = "Control Tower log group for cloud trail logs"
  default = "aws-controltower/CloudTrailLogs"

}

# Emails which will be notified 
variable "emails" {
  type = list
}

# OU where control will be applied
variable "ou" {
  description = "OU-id where Control Tower root controls (SCP) need to be applied"
}