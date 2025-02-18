## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.11"
    }
  }
}

module "configuration-jamf-pro-smart-groups" {
  source = "../configuration-jamf-pro-smart-groups"
}

module "configuration-jamf-pro-categories" {
  source = "../configuration-jamf-pro-categories"
}

module "configuration-jamf-pro-computer-management-settings" {
  source = "../configuration-jamf-pro-computer-management-settings"
}

module "management-iOS-configuration-profiles" {
  source                    = "../management-iOS-configuration-profiles"
  support_files_path_prefix = var.support_files_path_prefix
}

module "management-macOS-rosetta" {
  source = "../management-macOS-rosetta"
}

module "endpoint-security-macOS-filevault" {
  source                    = "../endpoint-security-macOS-filevault"
  support_files_path_prefix = var.support_files_path_prefix
}
