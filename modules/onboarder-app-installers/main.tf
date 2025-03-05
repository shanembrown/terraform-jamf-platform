## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.11"
    }
  }
}

variable "app_installers" {
  type = list(string)
  default = [
    "Adobe Creative Cloud",
    "Box Drive",
    "Dropbox",
    "Google Chrome",
    "Google Drive",
    "JamfCheck",
    "Microsoft Edge",
    "Mozilla Firefox",
    "Nudge",
    "Slack",
    "TextExpander",
    "Zoom Client for Meetings"
  ]
}

module "management-app-installers" {
  source             = "../management-app-installers"
  for_each           = toset(var.app_installers)
  app_installer_name = each.value
}
