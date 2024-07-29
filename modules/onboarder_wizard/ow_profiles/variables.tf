variable "prefix" {
  type    = string
  default = "Onboarding - "
}

variable "support_files_path_prefix" {
  type    = string
  default = ""
}

variable "block_beta_updates" {
  type = bool
  default = false
}

variable "enforce_firewall_and_gatekeeper" {
  type = bool
  default = false
}