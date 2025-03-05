## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.11"
    }
  }
}

module "management-app-installers" {
  source             = "../management-app-installers"
  for_each           = toset(var.app_installers)
  app_installer_name = each.value
}

module "microsoft_365" {
  source = "../management-app-installers-microsoft-365"
}
