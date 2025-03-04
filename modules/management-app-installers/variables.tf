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

variable "app_name" {
  description = "The name of the App for App Installer"
  type        = string
  default     = ""
}

variable "enabled" {
  description = "If the App Installer is enabled"
  type        = bool
  default     = true
}

variable "deployment_type" {
  description = "The type of deployment for App Installer (allowed values: INSTALL_AUTOMATICALLY or SELF_SERVICE)"
  type        = string
  default     = "INSTALL_AUTOMATICALLY"

  validation {
    condition     = var.deployment_type == "INSTALL_AUTOMATICALLY" || var.deployment_type == "SELF_SERVICE"
    error_message = "Allowed values for deployment_type are 'INSTALL_AUTOMATICALLY' or 'SELF_SERVICE'."
  }
}

variable "update_behavior" {
  description = "The update behavior for App Installer (allowed values: AUTOMATIC or MANUAL)"
  type        = string
  default     = "AUTOMATIC"

  validation {
    condition     = var.update_behavior == "AUTOMATIC" || var.update_behavior == "MANUAL"
    error_message = "Allowed values for update_behavior are 'AUTOMATIC' or 'MANUAL'."
  }
}

variable "trigger_admin_notifications" {
  description = "Log event notifications for this app. Opt in to receiving notifications for certain events including app updates and installation failures."
  type        = bool
  default     = true
}

variable "deadline" {
  description = "The Update deadline in hours."
  type        = number
  default     = 1
}

variable "quit_delay" {
  description = "Force quit grace period in minutes."
  type        = number
  default     = 1
}
