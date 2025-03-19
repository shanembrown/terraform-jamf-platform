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


variable "installomator_labels" {
  type = list(string)
  default = [
    "boxdrive",
    "dropbox",
    "googlechrome",
    "googledrive",
    "jamfcheck",
    "microsoftedge",
    "firefox",
    "nudge",
    "slack",
    "textexpander",
    "zoomclient"
  ]
}

variable "installomator_policy_titles" {
  type = list(string)
  default = [
    "Box Drive",
    "Dropbox",
    "Google Chrome",
    "Google Drive",
    "JamfCheck",
    "Microsoft Edge",
    "Firefox",
    "Nudge",
    "Slack",
    "TextExpander",
    "Zoom Client"
  ]
}
