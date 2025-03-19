## Root provider requirements
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
    jsc = {
      source  = "danjamf/jsctfprovider"
      version = ">= 0.0.23"
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
  hide_sensitive_data                  = true # Hides sensititve data in logs
  token_refresh_buffer_period_seconds  = 5    # minutes
  jamfpro_load_balancer_lock           = true
  mandatory_request_delay_milliseconds = 100
}

# JSC provider root configuration
provider "jsc" {
  username          = var.jsc_username
  password          = var.jsc_password
  applicationid     = var.jsc_applicationid
  applicationsecret = var.jsc_applicationsecret
}

# Onboarder Modules
module "onboarder-all" {
  count  = var.include_onboarder_all == true ? 1 : 0
  source = "./modules/onboarder-all"
}

module "onboarder-management-macOS" {
  count  = var.include_onboarder_management_macOS == true ? 1 : 0
  source = "./modules/onboarder-management-macOS"
}

module "onboarder-management-mobile" {
  count  = var.include_onboarder_management_mobile == true ? 1 : 0
  source = "./modules/onboarder-management-mobile"
}

module "onboarder-app-installers" {
  count  = var.include_onboarder_app_installers == true ? 1 : 0
  source = "./modules/onboarder-app-installers"
}

module "installomator-app-installers" {
  source                     = "./modules/installomator-app-installers"
  for_each                   = toset(var.installomator_labels)
  installomator_label        = each.value.label
  installomator_display_name = each.value.display_name
}


## Initialize common modules

## Initialize Protect (for macOS) module

module "configuration-jamf-pro-jamf-protect" {
  count                       = var.include_jamf_protect_trial_kickstart == true ? 1 : 0
  source                      = "./modules/configuration-jamf-pro-jamf-protect"
  jamfpro_instance_url        = var.jamfpro_instance_url
  jamfpro_client_id           = var.jamfpro_client_id
  jamfpro_client_secret       = var.jamfpro_client_secret
  jamfprotect_url             = var.jamfprotect_url
  jamfprotect_clientID        = var.jamfprotect_clientID
  jamfprotect_client_password = var.jamfprotect_client_password
}

module "compliance-macOS-cis-level-1" {
  count  = var.include_mac_cis_lvl1_benchmark == true ? 1 : 0
  source = "./modules/compliance-macOS-cis-level-1"
}

module "compliance-iOS-cis-level-1" {
  count  = var.include_mobile_cis_lvl1_benchmark == true ? 1 : 0
  source = "./modules/compliance-iOS-cis-level-1"
}

module "compliance-macOS-disa-stig" {
  count  = var.include_mac_stig_benchmark == true ? 1 : 0
  source = "./modules/compliance-macOS-disa-stig"
}

module "compliance-iOS-disa-stig" {
  count  = var.include_mobile_stig_benchmark == true ? 1 : 0
  source = "./modules/compliance-iOS-disa-stig"
}

module "compliance-macOS-nist-800-171" {
  count  = var.include_mac_800_171_benchmark == true ? 1 : 0
  source = "./modules/compliance-macOS-nist-800-171"
}

module "compliance-macOS-cmmc-level-1" {
  count  = var.include_mac_cmmc_lvl1_benchmark == true ? 1 : 0
  source = "./modules/compliance-macOS-cmmc-level-1"
}

module "configuration-jamf-pro-smart-groups" {
  count  = var.include_qol_smart_groups == true ? 1 : 0
  source = "./modules/configuration-jamf-pro-smart-groups"
}

module "management-macOS-microsoft-365" {
  count  = var.include_microsoft_365 == true ? 1 : 0
  source = "./modules/management-macOS-microsoft-365"
}

module "configuration-jamf-pro-categories" {
  count  = var.include_categories == true ? 1 : 0
  source = "./modules/configuration-jamf-pro-categories"
}

module "management-iOS-configuration-profiles" {
  count  = var.include_mobile_device_kickstart == true ? 1 : 0
  source = "./modules/management-iOS-configuration-profiles"
}

module "configuration-jamf-pro-computer-management-settings" {
  count  = var.include_computer_management_settings == true ? 1 : 0
  source = "./modules/configuration-jamf-pro-computer-management-settings"
}

module "endpoint-security-macOS-filevault" {
  count  = var.include_filevault == true ? 1 : 0
  source = "./modules/endpoint-security-macOS-filevault"
}

module "endpoint-security-macOS-microsoft-defender" {
  count  = var.include_defender == true ? 1 : 0
  source = "./modules/endpoint-security-macOS-microsoft-defender"
}

module "management-macOS-SSOe-Okta" {
  count  = var.include_ssoe_okta == true ? 1 : 0
  source = "./modules/management-macOS-SSOe-Okta"
}

module "endpoint-security-macOS-crowdstrike" {
  count  = var.include_crowdstrike == true ? 1 : 0
  source = "./modules/endpoint-security-macOS-crowdstrike"
}

module "management-macOS-rosetta" {
  count  = var.include_rosetta == true ? 1 : 0
  source = "./modules/management-macOS-rosetta"
}

module "management-app-installers" {
  source             = "./modules/management-app-installers"
  for_each           = toset(var.app_installers)
  app_installer_name = each.value
}

## Begin Jamf Security Cloud Configuration

## Create UEMC and Okta integrations
module "configuration-jamf-security-cloud-jamf-pro" {
  count                 = var.include_jsc_uemc == true ? 1 : 0
  source                = "./modules/configuration-jamf-security-cloud-jamf-pro"
  jamfpro_instance_url  = var.jamfpro_instance_url
  jamfpro_client_id     = var.jamfpro_client_id
  jamfpro_client_secret = var.jamfpro_client_secret
}

## Create Jamf Security Cloud Activation Profile containing ALL JSC Services
module "configuration-jamf-security-cloud-all-services" {
  count              = var.include_jsc_all_services == true ? 1 : 0
  source             = "./modules/configuration-jamf-security-cloud-all-services"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

module "network-security-access-policy" {
  source             = "./modules/network-security-access-policy"
  for_each           = toset(var.access_policies)
  access_policy_name = each.value
}

module "configuration-jamf-security-cloud-block-pages" {
  count           = var.include_jsc_block_pages == true ? 1 : 0
  source          = "./modules/configuration-jamf-security-cloud-block-pages"
  block_page_logo = var.block_page_logo
}

## Create Jamf Security Cloud Activation Profile containing ONLY Category Based Content Filtering
module "network-security-jamf-pro-content-filtering" {
  count              = var.include_jsc_dp_only == true ? 1 : 0
  source             = "./modules/network-security-jamf-pro-content-filtering"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Threat Response (MTD)
module "network-security-jamf-pro-network-threat-defense" {
  count              = var.include_jsc_mtd_only == true ? 1 : 0
  source             = "./modules/network-security-jamf-pro-network-threat-defense"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Threat Response (MTD)
module "network-security-jamf-pro-content-filtering-and-network-threat-defense" {
  count              = var.include_jsc_mtd_dp_only == true ? 1 : 0
  source             = "./modules/network-security-jamf-pro-content-filtering-and-network-threat-defense"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Connect ZTNA
module "network-security-jamf-pro-zero-trust-network-access" {
  count              = var.include_jsc_ztna == true ? 1 : 0
  source             = "./modules/network-security-jamf-pro-zero-trust-network-access"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Connect ZTNA
module "network-security-jamf-pro-zero-trust-network-access-and-content-filtering" {
  count              = var.include_jsc_ztna_dp_only == true ? 1 : 0
  source             = "./modules/network-security-jamf-pro-zero-trust-network-access-and-content-filtering"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Connect ZTNA
module "network-security-jamf-pro-zero-trust-network-access-and-network-threat-prevention" {
  count              = var.include_jsc_ztna_mtd_only == true ? 1 : 0
  source             = "./modules/network-security-jamf-pro-zero-trust-network-access-and-network-threat-prevention"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}
