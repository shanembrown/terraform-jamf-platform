## Define Jamf Pro provider variables (populated by .tfvars file)
variable "jamfpro_instance_url" {
  description = "Jamf Pro Instance name."
  type        = string
  default     = ""
}

variable "jamfpro_auth_method" {
  description = "Jamf Pro Auth Method."
  type        = string
  default     = "oauth2" #basic or oauth2
}

variable "jamfpro_client_id" {
  description = "Jamf Pro Client ID for authentication."
  type        = string
  default     = ""
}

variable "jamfpro_client_secret" {
  description = "Jamf Pro Client Secret for authentication."
  type        = string
  sensitive   = true
  default     = ""
}

variable "jamfpro_username" {
  description = "Jamf Pro username used for authentication."
  type        = string
  default     = ""
}

variable "jamfpro_password" {
  description = "Jamf Pro password used for authentication."
  type        = string
  sensitive   = true
  default     = ""
}


## Define JSC provider variables (populated by .tfvars file)
variable "radar_user" {
  type      = string
  sensitive = true
  default   = ""
}

variable "radar_pass" {
  type      = string
  sensitive = true
  default   = ""
}

variable "okta_jsc_id" {
  type      = string
  sensitive = true
  default   = "66a2acb005cb1b0b0929295b"
}

## Define Okta-related variables
variable "tje_okta_clientid" {
  type    = string
  default = "0oa1qa4x0qj2Jzeco1d8"
}

variable "tje_okta_orgdomain" {
  type    = string
  default = "jamf-harbor.okta.com"
}

## Define miscellaneous variables
variable "wizard_suffix" {
  type    = string
  default = " - TJE Provided"
}

## Define vingnette variables

variable "include_jamfpro_demo_config" {
  type    = bool
  default = true
}
variable "include_ej_incident_response" {
  type    = bool
  default = true
}

variable "include_ej_base" {
  type    = bool
  default = true
}

variable "include_ej_mac_cis_benchmark" {
  type    = bool
  default = true
}

variable "include_ej_mobile_cis_benchmark" {
  type    = bool
  default = true
}

variable "include_ej_secure_remote_access" {
  type    = bool
  default = true
}

variable "include_sandbox" {
  type    = bool
  default = true
}



## JSC Variables
variable "include_jsc_demo_config" {
  type    = bool
  default = true
}

variable "include_ej_jsc_ztna_only" {
  type    = bool
  default = true
}

variable "include_ej_jsc_dp_only" {
  type    = bool
  default = true
}

variable "include_ej_jsc_mtd_only" {
  type    = bool
  default = true
}

variable "include_ej_jsc_all_services" {
  type    = bool
  default = true
}

variable "include_ej_jsc_base" {
  type    = bool
  default = true
}

variable "include_ej_jsc_ztna_apps" {
  type    = bool
  default = true
}