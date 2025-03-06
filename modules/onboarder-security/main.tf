## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.11"
    }
    jsc = {
      source  = "danjamf/jsctfprovider"
      version = ">= 0.0.15"
    }
  }
}

module "configuration-jamf-security-cloud-all-services" {
  source                    = "../configuration-jamf-security-cloud-all-services"
  support_files_path_prefix = var.support_files_path_prefix
  tje_okta_clientid         = var.tje_okta_clientid
  tje_okta_orgdomain        = var.tje_okta_orgdomain
}

module "configuration-jamf-security-cloud-block-pages" {
  source          = "../configuration-jamf-security-cloud-block-pages"
  block_page_logo = var.block_page_logo
}

module "endpoint-security-macOS-filevault" {
  source                    = "../endpoint-security-macOS-filevault"
  support_files_path_prefix = var.support_files_path_prefix
}

# module "configuration-jamf-security-cloud-jamf-pro" {
#   source               = "../configuration-jamf-security-cloud-jamf-pro"
#   tje_okta_clientid    = var.tje_okta_clientid
#   tje_okta_orgdomain   = var.tje_okta_orgdomain
#   jamfpro_instance_url = var.jamfpro_instance_url
#   clientid             = var.jamfpro_client_id
#   clientsecret         = var.jamfpro_client_secret
# }

# module "configuration-jamf-pro-jamf-protect" {
#   source                      = "../configuration-jamf-pro-jamf-protect"
#   support_files_path_prefix   = var.support_files_path_prefix
#   jamfpro_instance_url        = var.jamfpro_instance_url
#   jamfpro_client_id           = var.jamfpro_client_id
#   jamfpro_client_secret       = var.jamfpro_client_secret
#   jamfprotect_url             = var.jamfprotect_url
#   jamfprotect_clientID        = var.jamfprotect_clientID
#   jamfprotect_client_password = var.jamfprotect_client_password
# }
