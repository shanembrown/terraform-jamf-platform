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
  source                    = "./modules/onboarder-all"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-management-macOS" {
  source                    = "./modules/onboarder-management-macOS"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-management-mobile" {
  source                    = "./modules/onboarder-management-mobile"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-security" {
  source                    = "./modules/onboarder-security"
  support_files_path_prefix = var.support_files_path_prefix
}

module "onboarder-app-installers" {
  source                    = "./modules/onboarder-app-installers"
  support_files_path_prefix = var.support_files_path_prefix
}

## Initialize common modules

## Initialize Protect (for macOS) module

module "configuration-jamf-pro-jamf-protect" {
  source                      = "./modules/configuration-jamf-pro-jamf-protect"
  jamfpro_instance_url        = var.jamfpro_instance_url
  jamfpro_client_id           = var.jamfpro_client_id
  jamfpro_client_secret       = var.jamfpro_client_secret
  jamfprotect_url             = var.jamfprotect_url
  jamfprotect_clientID        = var.jamfprotect_clientID
  jamfprotect_client_password = var.jamfprotect_client_password
}

module "compliance-macOS-cis-level-1" {
  source                    = "./modules/compliance-macOS-cis-level-1"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-iOS-cis-level-1" {
  source                    = "./modules/compliance-iOS-cis-level-1"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-macOS-disa-stig" {
  source                    = "./modules/compliance-macOS-disa-stig"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-iOS-disa-stig" {
  source                    = "./modules/compliance-iOS-disa-stig"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-macOS-nist-800-171" {
  source                    = "./modules/compliance-macOS-nist-800-171"
  support_files_path_prefix = var.support_files_path_prefix
}

module "compliance-macOS-cmmc-level-1" {
  source                    = "./modules/compliance-macOS-cmmc-level-1"
  support_files_path_prefix = var.support_files_path_prefix
}

module "configuration-jamf-pro-smart-groups" {
  source = "./modules/configuration-jamf-pro-smart-groups"
}

module "management-app-installers-microsoft-365" {
  source = "./modules/management-app-installers-microsoft-365"
}

module "configuration-jamf-pro-categories" {
  source = "./modules/configuration-jamf-pro-categories"
}

module "management-iOS-configuration-profiles" {
  source = "./modules/management-iOS-configuration-profiles"
}

module "configuration-jamf-pro-computer-management-settings" {
  source = "./modules/configuration-jamf-pro-computer-management-settings"
}

module "endpoint-security-macOS-filevault" {
  source = "./modules/endpoint-security-macOS-filevault"
}

module "endpoint-security-macOS-microsoft-defender" {
  source = "./modules/endpoint-security-macOS-microsoft-defender"
}

module "management-macOS-passwordless-sso" {
  source                    = "./modules/management-macOS-passwordless-sso"
  support_files_path_prefix = var.support_files_path_prefix
}

module "endpoint-security-macOS-crowdstrike" {
  source = "./modules/endpoint-security-macOS-crowdstrike"
}


module "management-macOS-rosetta" {
  source = "./modules/management-macOS-rosetta"
}

module "management-app-installers-box-drive" {
  source = "./modules/management-app-installers-box-drive"
}

module "management-app-installers-nudge" {
  source = "./modules/management-app-installers-nudge"
}

module "management-app-installers-adobe-creative-cloud" {
  source = "./modules/management-app-installers-adobe-creative-cloud"
}

module "management-app-installers-text-expander" {
  source = "./modules/management-app-installers-text-expander"
}

module "management-app-installers-microsoft-edge" {
  source = "./modules/management-app-installers-microsoft-edge"
}

module "management-app-installers-google-chrome" {
  source = "./modules/management-app-installers-google-chrome"
}

module "management-app-installers-mozilla-firefox" {
  source = "./modules/management-app-installers-mozilla-firefox"
}

module "management-app-installers-slack" {
  source = "./modules/management-app-installers-slack"
}

module "management-app-installers-dropbox" {
  source = "./modules/management-app-installers-dropbox"
}

module "management-app-installers-google-drive" {
  source = "./modules/management-app-installers-google-drive"
}

module "management-app-installers-jamf-composer" {
  source = "./modules/management-app-installers-jamf-composer"
}

module "management-app-installers-pppc-utility" {
  source = "./modules/management-app-installers-pppc-utility"
}

module "management-app-installers-jamfcheck" {
  source = "./modules/management-app-installers-jamfcheck"
}

module "management-app-installers-zoom" {
  source = "./modules/management-app-installers-zoom"
}

## Begin Jamf Security Cloud Configuration

## Create UEMC and Okta integrations
module "configuration-jamf-security-cloud-jamf-pro" {
  source               = "./modules/configuration-jamf-security-cloud-jamf-pro"
  tje_okta_clientid    = var.tje_okta_clientid
  tje_okta_orgdomain   = var.tje_okta_orgdomain
  jamfpro_instance_url = var.jamfpro_instance_url
  clientid             = var.jamfpro_client_id
  clientsecret         = var.jamfpro_client_secret
}

## Create Jamf Security Cloud Activation Profile containing ALL JSC Services
module "configuration-jamf-security-cloud-all-services" {
  source             = "./modules/configuration-jamf-security-cloud-all-services"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

module "network-security-access-policy-adobe" {
  source = "./modules/network-security-access-policy-adobe"
}

module "network-security-access-policy-atlassian" {
  source = "./modules/network-security-access-policy-atlassian"
}

module "network-security-access-policy-bluejeans" {
  source = "./modules/network-security-access-policy-bluejeans"
}

module "network-security-access-policy-box" {
  source = "./modules/network-security-access-policy-box"
}

module "network-security-access-policy-docusign" {
  source = "./modules/network-security-access-policy-docusign"
}

module "network-security-access-policy-dropbox" {
  source = "./modules/network-security-access-policy-dropbox"
}

module "network-security-access-policy-github" {
  source = "./modules/network-security-access-policy-github"
}

module "network-security-access-policy-google" {
  source = "./modules/network-security-access-policy-google"
}

module "network-security-access-policy-hubspot" {
  source = "./modules/network-security-access-policy-hubspot"
}

module "network-security-access-policy-mailchimp" {
  source = "./modules/network-security-access-policy-mailchimp"
}

module "network-security-access-policy-mathworks" {
  source = "./modules/network-security-access-policy-mathworks"
}

module "network-security-access-policy-microsoft" {
  source = "./modules/network-security-access-policy-microsoft"
}

module "network-security-access-policy-my-ip" {
  source = "./modules/network-security-access-policy-my-ip"
}

module "network-security-access-policy-okta" {
  source = "./modules/network-security-access-policy-okta"
}

module "network-security-access-policy-salesforce" {
  source = "./modules/network-security-access-policy-salesforce"
}

module "network-security-access-policy-servicenow" {
  source = "./modules/network-security-access-policy-servicenow"
}

module "network-security-access-policy-slack" {
  source = "./modules/network-security-access-policy-slack"
}

module "network-security-access-policy-snowflake" {
  source = "./modules/network-security-access-policy-snowflake"
}

module "network-security-access-policy-splunk" {
  source = "./modules/network-security-access-policy-splunk"
}

module "network-security-access-policy-square" {
  source = "./modules/network-security-access-policy-square"
}

module "network-security-access-policy-twilio" {
  source = "./modules/network-security-access-policy-twilio"
}

module "network-security-access-policy-webex" {
  source = "./modules/network-security-access-policy-webex"
}

module "network-security-access-policy-workday" {
  source = "./modules/network-security-access-policy-workday"
}

module "network-security-access-policy-zendesk" {
  source = "./modules/network-security-access-policy-zendesk"
}

module "network-security-access-policy-zoom" {
  source = "./modules/network-security-access-policy-zoom"
}

module "configuration-jamf-security-cloud-block-pages" {
  source          = "./modules/configuration-jamf-security-cloud-block-pages"
  block_page_logo = var.block_page_logo
}

## Create Jamf Security Cloud Activation Profile containing ONLY Category Based Content Filtering
module "network-security-jamf-pro-content-filtering" {
  source             = "./modules/network-security-jamf-pro-content-filtering"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Threat Response (MTD) 
module "network-security-jamf-pro-network-threat-defense" {
  source             = "./modules/network-security-jamf-pro-network-threat-defense"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Threat Response (MTD) 
module "network-security-jamf-pro-content-filtering-and-network-threat-defense" {
  source             = "./modules/network-security-jamf-pro-content-filtering-and-network-threat-defense"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Connect ZTNA
module "network-security-jamf-pro-zero-trust-network-access" {
  source             = "./modules/network-security-jamf-pro-zero-trust-network-access"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Connect ZTNA
module "network-security-jamf-pro-zero-trust-network-access-and-content-filtering" {
  source             = "./modules/network-security-jamf-pro-zero-trust-network-access-and-content-filtering"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}

## Create Jamf Security Cloud Activation Profile containing ONLY Connect ZTNA
module "network-security-jamf-pro-zero-trust-network-access-and-network-threat-prevention" {
  source             = "./modules/network-security-jamf-pro-zero-trust-network-access-and-network-threat-prevention"
  tje_okta_clientid  = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
}
