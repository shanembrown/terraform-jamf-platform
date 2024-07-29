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

## Define Okta-related variables
variable "tje_okta_clientid" {
  type    = string
  default = "0oa1qa4x0qj2Jzeco1d8"
}

variable "tje_okta_orgdomain" {
  type    = string
  default = "jamf-harbor.okta.com"
}

## Define onboarder wizard variables
variable "include_onboarder_wizard" {
  type    = bool
  default = false
}

variable "install_chrome" {
  type    = bool
  default = false
}

variable "install_firefox" {
  type    = bool
  default = false
}

variable "block_beta_updates" {
  type    = bool
  default = false
}

variable "enforce_firewall_and_gatekeeper" {
  type    = bool
  default = false
}

## Define vingnette variables
variable "include_jamfpro_prerequisites" {
  type    = bool
  default = false
}

variable "include_ej_base" {
  type    = bool
  default = false
}

variable "include_ej_saas_tenancy" {
  type    = bool
  default = false
}

variable "include_ej_incident_response" {
  type    = bool
  default = false
}

variable "include_ej_mac_cis_benchmark" {
  type    = bool
  default = false
}

variable "include_ej_mobile_cis_benchmark" {
  type    = bool
  default = false
}

variable "include_ej_secure_remote_access" {
  type    = bool
  default = false
}

## Define demo config variables
variable "include_jsc_demo_config" {
  type    = bool
  default = false
}

variable "include_sandbox" {
  type    = bool
  default = false
}

variable "include_jamfpro_demo_config" {
  type    = bool
  default = false
}

variable "include_jsc_dp_only" {
  type    = bool
  default = false
}

variable "include_jsc_mtd_only" {
  type    = bool
  default = false
}

variable "include_jsc_all_services" {
  type    = bool
  default = false
}

variable "include_jsc_base" {
  type    = bool
  default = false
}

variable "include_jsc_ztna" {
  type    = bool
  default = false
}

variable "include_jsc_block_pages" {
  type    = bool
  default = false
}

variable "include_ej_jsc_config" {
  type    = bool
  default = false
}

variable "jsc_provided_idp_client" {
  type    = string
  default = ""
}

variable "wizard_suffix" {
  type    = string
  default = ""
}

variable "block_page_logo" {
  type      = string
  sensitive = true
  default   = ""
}

