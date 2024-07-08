## Root provider requirements
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
    jsc = {
      source = "danjamf/jsctfprovider"
      version = "0.0.5"
    }
  }
}


## Jamf Pro provider root configuration
provider "jamfpro" {
  jamfpro_instance_fqdn          = var.jamfpro_instance_url
  auth_method =               "basic" // oauth2
  basic_auth_username = var.jamfpro_username
  basic_auth_password = var.jamfpro_password
  #client_id                   = var.jamfpro_client_id
  #client_secret               = var.jamfpro_client_secret
  enable_client_sdk_logs                 = false
  hide_sensitive_data         = true # Hides sensitive data in logs
  token_refresh_buffer_period_seconds = 5 # minutes
  jamfpro_load_balancer_lock     = true
  mandatory_request_delay_milliseconds = 100
}

## Initialize Jamf Pro child modules
module "jamfpro_settings" {
  source = "./modules/jamfpro_config/"
  include_jamfpro_departments = var.include_jamfpro_departments
}


## JSC provider root configuration
provider "jsc" {
  # Configure provider-specific settings if needed
  username   = var.radar_user
  password   = var.radar_pass
  //customerid = var.radar_customerid
}

## Initialiaze JSC child modules
module "jsc_config" {
  source = "./modules/jsc_config/"
  jamfpro_instance_url = var.jamfpro_instance_url
  radar_user = var.radar_user
  tje_okta_clientid = var.tje_okta_clientid
  tje_okta_orgdomain = var.tje_okta_orgdomain
  wizard_suffix = var.wizard_suffix
}