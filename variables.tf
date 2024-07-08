## Define Jamf Pro provider variables (populated by .tfvars file)
variable "jamfpro_instance_url" {
  description = "Jamf Pro Instance name."
  default     = ""
}

variable "jamfpro_client_id" {
  description = "Jamf Pro Client ID for authentication."
  default     = ""
}

variable "jamfpro_client_secret" {
  description = "Jamf Pro Client Secret for authentication."
  sensitive   = true
  default     = ""
}

variable "jamfpro_username" {
  description = "Jamf Pro username used for authentication."
  default     = ""
}

variable "jamfpro_password" {
  description = "Jamf Pro password used for authentication."
  sensitive   = true
  default     = ""
}


## Define JSC provider variables (populated by .tfvars file)
variable "radar_user" {
  type = string
  default = ""
}

variable "radar_pass" {
  type = string
  sensitive = true
  default = ""
}

## Define Jamf Pro config knobs
variable "include_jamfpro_departments" {
  type = string
  default = "false"
}

## Define Okta-related variables
variable "tje_okta_clientid" {
  type = string
  default = "0oa1qa4x0qj2Jzeco1d8"
}

variable "tje_okta_orgdomain" {
  type = string
  default = "jamf-harbor.okta.com"
}

## Define miscellaneous variables
variable "wizard_suffix" {
  type    = string
  default = " - TJE Provided"
}