## Define Jamf Pro provider variables
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


## Define JSC provider variables
variable "radar_user" {
  type = string
  default = ""
}

variable "radar_pass" {
  type = string
  sensitive = true
  default = ""
}