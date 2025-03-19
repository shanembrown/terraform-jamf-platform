## Define miscellaneous variables
variable "prefix" {
  type    = string
  default = "EJ - "
}

variable "support_files_path_prefix" {
  type    = string
  default = ""
}
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

variable "script_priority" {
  type    = string
  default = "AFTER"
}

variable "script_info" {
  type    = string
  default = ""
}

variable "installomator_labels" {
  description = "Set of selected Installomator Labels"
  type        = list(tuple([string, string]))
  default     = []
}

variable "installomator_label" {
  type    = string
  default = ""
}

variable "installomator_display_name" {
  type    = string
  default = ""
}
