resource "random_string" "random" {
  length           = 2
  special          = false
  override_special = "/@£$"
}

variable "wizard_suffix" {
  type    = string
  default = " - TJE Provided"
}

variable "tje_okta_clientid" {
  type = string
  default = "0oa1qa4x0qj2Jzeco1d8"
}

variable "tje_okta_orgdomain" {
  type = string
  default = "jamf-harbor.okta.com"
}