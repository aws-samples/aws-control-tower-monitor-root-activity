#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: MIT-0

#Default AWS ControlTower Log Group
variable "ct_log_group" {
  description = "Control Tower log group for cloud trail logs"
  default     = "aws-controltower/CloudTrailLogs"

}

# Emails which will recieve the notifications 
variable "emails" {
  type = list(any)
}


variable "ou" {
  description = "OU-id where Control Tower root controls (SCP) need to be applied"
}
