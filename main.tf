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
  count                     = var.include_onboarder_all == true ? 1 : 0
  source                    = "./modules/onboarder-all"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-management-macOS" {
  count                     = var.include_onboarder_management_macOS == true ? 1 : 0
  source                    = "./modules/onboarder-management-macOS"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-management-mobile" {
  count                     = var.include_onboarder_management_mobile == true ? 1 : 0
  source                    = "./modules/onboarder-management-mobile"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-security" {
  count                     = var.include_onboarder_security == true ? 1 : 0
  source                    = "./modules/onboarder-security"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-app-installers" {
  count                     = var.include_onboarder_app_installers == true ? 1 : 0
  source                    = "./modules/onboarder-app-installers"
  support_files_path_prefix = var.support_files_path_prefix
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
  count                     = var.include_mac_cis_lvl1_benchmark == true ? 1 : 0
  source                    = "./modules/compliance-macOS-cis-level-1"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-iOS-cis-level-1" {
  count                     = var.include_mobile_cis_lvl1_benchmark == true ? 1 : 0
  source                    = "./modules/compliance-iOS-cis-level-1"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-macOS-disa-stig" {
  count                     = var.include_mac_stig_benchmark == true ? 1 : 0
  source                    = "./modules/compliance-macOS-disa-stig"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-iOS-disa-stig" {
  count                     = var.include_mobile_stig_benchmark == true ? 1 : 0
  source                    = "./modules/compliance-iOS-disa-stig"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-macOS-nist-800-171" {
  count                     = var.include_mac_800_171_benchmark == true ? 1 : 0
  source                    = "./modules/compliance-macOS-nist-800-171"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-macOS-cmmc-level-1" {
  count                     = var.include_mac_cmmc_lvl1_benchmark == true ? 1 : 0
  source                    = "./modules/compliance-macOS-cmmc-level-1"
  support_files_path_prefix = var.support_files_path_prefix
}

module "configuration-jamf-pro-smart-groups" {
  count  = var.include_qol_smart_groups == true ? 1 : 0
  source = "./modules/configuration-jamf-pro-smart-groups"
}

module "management-app-installers-microsoft-365" {
  count  = var.include_microsoft_365 == true ? 1 : 0
  source = "./modules/management-app-installers-microsoft-365"
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
  count                     = var.include_ssoe-okta == true ? 1 : 0
  source                    = "./modules/management-macOS-SSOe-Okta"
  support_files_path_prefix = var.support_files_path_prefix
}

module "endpoint-security-macOS-crowdstrike" {
  count  = var.include_crowdstrike == true ? 1 : 0
  source = "./modules/endpoint-security-macOS-crowdstrike"
}

module "management-macOS-rosetta" {
  count  = var.include_rosetta == true ? 1 : 0
  source = "./modules/management-macOS-rosetta"
}

module "management-app-installers-box-drive" {
  count  = var.include_box_drive == true ? 1 : 0
  source = "./modules/management-app-installers-box-drive"
}

module "management-app-installers-nudge" {
  count  = var.include_nudge == true ? 1 : 0
  source = "./modules/management-app-installers-nudge"
}

module "management-app-installers-adobe-creative-cloud" {
  count  = var.include_adobe_creative_cloud == true ? 1 : 0
  source = "./modules/management-app-installers-adobe-creative-cloud"
}

module "management-app-installers-text-expander" {
  count  = var.include_text_expander == true ? 1 : 0
  source = "./modules/management-app-installers-text-expander"
}

module "management-app-installers-microsoft-edge" {
  count  = var.include_microsoft_edge == true ? 1 : 0
  source = "./modules/management-app-installers-microsoft-edge"
}

module "management-app-installers-google-chrome" {
  count  = var.include_google_chrome == true ? 1 : 0
  source = "./modules/management-app-installers-google-chrome"
}

module "management-app-installers-mozilla-firefox" {
  count  = var.include_mozilla_firefox == true ? 1 : 0
  source = "./modules/management-app-installers-mozilla-firefox"
}

module "management-app-installers-slack" {
  count  = var.include_slack == true ? 1 : 0
  source = "./modules/management-app-installers-slack"
}

module "management-app-installers-dropbox" {
  count  = var.include_dropbox == true ? 1 : 0
  source = "./modules/management-app-installers-dropbox"
}

module "management-app-installers-google-drive" {
  count  = var.include_google_drive == true ? 1 : 0
  source = "./modules/management-app-installers-google-drive"
}

module "management-app-installers-jamf-composer" {
  count  = var.include_jamf_composer == true ? 1 : 0
  source = "./modules/management-app-installers-jamf-composer"
}

module "management-app-installers-pppc-utility" {
  count  = var.include_pppc_utility == true ? 1 : 0
  source = "./modules/management-app-installers-pppc-utility"
}

module "management-app-installers-jamfcheck" {
  count  = var.include_jamfcheck == true ? 1 : 0
  source = "./modules/management-app-installers-jamfcheck"
}

module "management-app-installers-zoom" {
  count  = var.include_zoom == true ? 1 : 0
  source = "./modules/management-app-installers-zoom"
}

module "management-app-installers" {
  source         = "./modules/management-app-installers"
  app_installers = var.app_installers
}

## Begin Jamf Security Cloud Configuration

## Create UEMC and Okta integrations
module "configuration-jamf-security-cloud-jamf-pro" {
  count                = var.include_jsc_uemc == true ? 1 : 0
  source               = "./modules/configuration-jamf-security-cloud-jamf-pro"
  tje_okta_clientid    = var.tje_okta_clientid
  tje_okta_orgdomain   = var.tje_okta_orgdomain
  jamfpro_instance_url = var.jamfpro_instance_url
  clientid             = var.jamfpro_client_id
  clientsecret         = var.jamfpro_client_secret
}

## Create Jamf Security Cloud Activation Profile containing ALL JSC Services
module "configuration-jamf-security-cloud-all-services" {
  count              = var.include_jsc_all_services == true ? 1 : 0
  source             = "./modules/configuration-jamf-security-cloud-all-services"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

module "network-security-access-policy-adobe" {
  count  = var.include_jsc_ap_adobe == true ? 1 : 0
  source = "./modules/network-security-access-policy-adobe"
}

module "network-security-access-policy-atlassian" {
  count  = var.include_jsc_ap_atlassian == true ? 1 : 0
  source = "./modules/network-security-access-policy-atlassian"
}

module "network-security-access-policy-bluejeans" {
  count  = var.include_jsc_ap_bluejeans == true ? 1 : 0
  source = "./modules/network-security-access-policy-bluejeans"
}

module "network-security-access-policy-box" {
  count  = var.include_jsc_ap_box == true ? 1 : 0
  source = "./modules/network-security-access-policy-box"
}

module "network-security-access-policy-docusign" {
  count  = var.include_jsc_ap_docusign == true ? 1 : 0
  source = "./modules/network-security-access-policy-docusign"
}

module "network-security-access-policy-dropbox" {
  count  = var.include_jsc_ap_dropbox == true ? 1 : 0
  source = "./modules/network-security-access-policy-dropbox"
}

module "network-security-access-policy-github" {
  count  = var.include_jsc_ap_github == true ? 1 : 0
  source = "./modules/network-security-access-policy-github"
}

module "network-security-access-policy-google" {
  count  = var.include_jsc_ap_google == true ? 1 : 0
  source = "./modules/network-security-access-policy-google"
}

module "network-security-access-policy-hubspot" {
  count  = var.include_jsc_ap_hubspot == true ? 1 : 0
  source = "./modules/network-security-access-policy-hubspot"
}

module "network-security-access-policy-mailchimp" {
  count  = var.include_jsc_ap_mailchimp == true ? 1 : 0
  source = "./modules/network-security-access-policy-mailchimp"
}

module "network-security-access-policy-mathworks" {
  count  = var.include_jsc_ap_mathworks == true ? 1 : 0
  source = "./modules/network-security-access-policy-mathworks"
}

module "network-security-access-policy-microsoft" {
  count  = var.include_jsc_ap_microsoft == true ? 1 : 0
  source = "./modules/network-security-access-policy-microsoft"
}

module "network-security-access-policy-my-ip" {
  count  = var.include_jsc_ap_my_ip == true ? 1 : 0
  source = "./modules/network-security-access-policy-my-ip"
}

module "network-security-access-policy-okta" {
  count  = var.include_jsc_ap_okta == true ? 1 : 0
  source = "./modules/network-security-access-policy-okta"
}

module "network-security-access-policy-salesforce" {
  count  = var.include_jsc_ap_salesforce == true ? 1 : 0
  source = "./modules/network-security-access-policy-salesforce"
}

module "network-security-access-policy-servicenow" {
  count  = var.include_jsc_ap_servicenow == true ? 1 : 0
  source = "./modules/network-security-access-policy-servicenow"
}

module "network-security-access-policy-slack" {
  count  = var.include_jsc_ap_slack == true ? 1 : 0
  source = "./modules/network-security-access-policy-slack"
}

module "network-security-access-policy-snowflake" {
  count  = var.include_jsc_ap_snowflake == true ? 1 : 0
  source = "./modules/network-security-access-policy-snowflake"
}

module "network-security-access-policy-splunk" {
  count  = var.include_jsc_ap_splunk == true ? 1 : 0
  source = "./modules/network-security-access-policy-splunk"
}

module "network-security-access-policy-square" {
  count  = var.include_jsc_ap_square == true ? 1 : 0
  source = "./modules/network-security-access-policy-square"
}

module "network-security-access-policy-twilio" {
  count  = var.include_jsc_ap_twilio == true ? 1 : 0
  source = "./modules/network-security-access-policy-twilio"
}

module "network-security-access-policy-webex" {
  count  = var.include_jsc_ap_webex == true ? 1 : 0
  source = "./modules/network-security-access-policy-webex"
}

module "network-security-access-policy-workday" {
  count  = var.include_jsc_ap_workday == true ? 1 : 0
  source = "./modules/network-security-access-policy-workday"
}

module "network-security-access-policy-zendesk" {
  count  = var.include_jsc_ap_zendesk == true ? 1 : 0
  source = "./modules/network-security-access-policy-zendesk"
}

module "network-security-access-policy-zoom" {
  count  = var.include_jsc_ap_zoom == true ? 1 : 0
  source = "./modules/network-security-access-policy-zoom"
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
