/*
Trial Baseline For Mobile Devices
  Passcode requirements
  Hide apple apps
  Restrict airdrop
  Restrict Apple ID changes
  Restrict camera
  Restrict erase all content and settings
  Restrict screenshots
*/

terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "mobile_device_configuration_profile_restrict_apple_id_changes" {
  name               = "Restrict Apple ID Changes"
  description        = "This restricts the ability to modify account settings for Apple ID"
  deployment_method  = "Install Automatically"
  level              = "Device Level"
  redeploy_on_update = "Newly Assigned"
  payloads           = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/mobile_device_kickstart/support_files/restrict_appleid_changes.mobileconfig")

  scope {
    all_mobile_devices = false
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "mobile_device_configuration_profile_restrict_airdrop" {
  name               = "Restrict Airdrop"
  description        = "This restricts the ability to use Airdrop"
  deployment_method  = "Install Automatically"
  level              = "Device Level"
  redeploy_on_update = "Newly Assigned"
  payloads           = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/mobile_device_kickstart/support_files/restrict_airdrop.mobileconfig")

  scope {
    all_mobile_devices = false
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "mobile_device_configuration_profile_passcode_requirements" {
  name               = "Passcode Requirements"
  description        = "Enforces a non complex 6 digit passcode"
  deployment_method  = "Install Automatically"
  level              = "Device Level"
  redeploy_on_update = "Newly Assigned"
  payloads           = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/mobile_device_kickstart/support_files/passcode_requirements.mobileconfig")

  scope {
    all_mobile_devices = false
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "mobile_device_configuration_profile_restrict_erase_all_content_and_settings" {
  name               = "Restrict Erase all Content and Settings"
  description        = "Restricts Erase all Content and Settings"
  deployment_method  = "Install Automatically"
  level              = "Device Level"
  redeploy_on_update = "Newly Assigned"
  payloads           = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/mobile_device_kickstart/support_files/restrict_erase_content_and_settings.mobileconfig")

  scope {
    all_mobile_devices = false
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "mobile_device_configuration_profile_restrict_camera" {
  name               = "Restrict Camera"
  description        = "Restricts the Camera in all Use and Apps"
  deployment_method  = "Install Automatically"
  level              = "Device Level"
  redeploy_on_update = "Newly Assigned"
  payloads           = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/mobile_device_kickstart/support_files/restrict_camera.mobileconfig")

  scope {
    all_mobile_devices = false
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "mobile_device_configuration_profile_restrict_screenshots" {
  name               = "Restrict Screenshots"
  description        = "Restricts the Ability to take Screenshots"
  deployment_method  = "Install Automatically"
  level              = "Device Level"
  redeploy_on_update = "Newly Assigned"
  payloads           = file("${var.support_files_path_prefix}modules/onboarder_modules/jamf_pro_trial_kickstart/mobile_device_kickstart/support_files/restrict_screenshots.mobileconfig")

  scope {
    all_mobile_devices = false
  }
}
