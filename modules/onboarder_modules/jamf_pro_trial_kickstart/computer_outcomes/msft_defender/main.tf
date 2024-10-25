## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}

## Create Categories
resource "jamfpro_category" "category_defender" {
  name     = "Windows Defender"
  priority = 9
}

## Create Configuration Profile

resource "jamfpro_macos_configuration_profile_plist" "jamfpro_macos_configuration_defender_pppc" {
  name                = "Windows Defender Standard Permissions"
  description         = "Source: https://learn.microsoft.com/en-us/defender-endpoint/mac-install-with-jamf"
  level               = "System"
  category_id         = jamfpro_category.category_defender.id
  redeploy_on_update  = "Newly Assigned"
  distribution_method = "Install Automatically"
  payloads            = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/computer_outcomes/msft_defender/support_files/defender.mobileconfig")
  payload_validate    = false
  user_removable      = false

  scope {
    all_computers = true
    all_jss_users = false
  }
}

## Create Microsoft Defender Appinstaller
resource "jamfpro_app_installer" "jamfpro_app_installer_microsoft_defender" {
  name            = "Microsoft Defender"
  enabled         = true
  deployment_type = "INSTALL_AUTOMATICALLY"
  update_behavior = "MANUAL"
  category_id     = jamfpro_category.category_defender.id
  site_id         = "-1"
  smart_group_id  = "1"

  install_predefined_config_profiles = true
  trigger_admin_notifications        = true

  notification_settings {
    notification_message  = ""
    notification_interval = 1
    deadline_message      = "Update deadline approaching"
    deadline              = 1
    quit_delay            = 1
    complete_message      = "Update completed successfully"
    relaunch              = true
    suppress              = false
  }

  self_service_settings {
    include_in_featured_category   = true
    include_in_compliance_category = false
    force_view_description         = false
    description                    = ""
  }
}