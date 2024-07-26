## Root provider requirements
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
    jsc = {
      source  = "danjamf/jsctfprovider"
      version = "0.0.5"
    }
  }
}

## Jamf Pro provider root configuration
provider "jamfpro" {
  jamfpro_instance_fqdn                = var.jamfpro_instance_url
  auth_method                          = var.jamfpro_auth_method
  basic_auth_username                  = var.jamfpro_username
  basic_auth_password                  = var.jamfpro_password
  client_id                            = var.jamfpro_client_id
  client_secret                        = var.jamfpro_client_secret
  enable_client_sdk_logs               = false
  hide_sensitive_data                  = true # Hides sensitive data in logs
  token_refresh_buffer_period_seconds  = 300
  jamfpro_load_balancer_lock           = false
  mandatory_request_delay_milliseconds = 100
}

## JSC provider root configuration
provider "jsc" {
  username = var.radar_user
  password = var.radar_pass
  #customerid = var.radar_customerid
}

## Initialize common modules
module "jamfpro_prerequisites" {
  count  = var.include_jamfpro_prerequisites == true ? 1 : 0
  source = "./modules/jamfpro_prerequisites/"
}

module "jamfpro_demo_config" {
  count  = var.include_jamfpro_demo_config == true ? 1 : 0
  source = "./modules/jamfpro_demo_config/"
}

module "jsc_demo_config" {
  count                = var.include_jsc_demo_config == true ? 1 : 0
  source               = "./modules/jsc_demo_config/"
  jamfpro_instance_url = var.jamfpro_instance_url
  radar_user           = var.radar_user
  tje_okta_clientid    = var.tje_okta_clientid
  tje_okta_orgdomain   = var.tje_okta_orgdomain
}

## Initialize Onboarding Wizard modules
module "ow_browsers" {
  count  = var.include_onboarder_wizard == true ? 1 : 0
  source = "./modules/onboarder_wizard/ow_browsers"
  support_files_path_prefix = "modules/onboarder_wizard//ow_browsers/"
  install_chrome = var.install_chrome
  install_firefox = var.install_firefox
}

module "ow_profiles" {
  count  = var.include_onboarder_wizard == true ? 1 : 0
  source = "./modules/onboarder_wizard/ow_profiles"
  support_files_path_prefix = "modules/onboarder_wizard//ow_profiles/"
  block_beta_updates = var.block_beta_updates
  enforce_firewall_and_gatekeeper = var.enforce_firewall_and_gatekeeper
}

## Initialize Experience Jamf vignette modules
module "ej_base" {
  count  = var.include_ej_base == true ? 1 : 0
  source = "./modules/experience_jamf_vignettes/ej_base"
}

module "ej_saas_tenancy" {
  count                     = var.include_ej_saas_tenancy == true ? 1 : 0
  source                    = "./modules/experience_jamf_vignettes/ej_saas_tenancy"
  support_files_path_prefix = "modules/experience_jamf_vignettes/ej_saas_tenancy/"
}

module "ej_incident_response" {
  count                     = var.include_ej_incident_response == true ? 1 : 0
  source                    = "./modules/experience_jamf_vignettes/ej_incident_response"
  support_files_path_prefix = "modules/experience_jamf_vignettes/ej_incident_response/"
}

module "ej_mac_cis_benchmark" {
  count                     = var.include_ej_mac_cis_benchmark == true ? 1 : 0
  source                    = "./modules/experience_jamf_vignettes/ej_mac_cis_benchmark"
  support_files_path_prefix = "modules/experience_jamf_vignettes/ej_mac_cis_benchmark/"
}

module "ej_mobile_cis_benchmark" {
  count  = var.include_ej_mobile_cis_benchmark == true ? 1 : 0
  source = "./modules/experience_jamf_vignettes/ej_mobile_cis_benchmark"
}

module "ej_secure_remote_access" {
  count  = var.include_ej_secure_remote_access == true ? 1 : 0
  source = "./modules/experience_jamf_vignettes/ej_secure_remote_access"
}

## Initialize sandbox module
module "sandbox" {
  count  = var.include_sandbox == true ? 1 : 0
  source = "./modules/sandbox"
}