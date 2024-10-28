## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}
## Profile data sources
data "http" "defender_combined" {
  url = "https://raw.githubusercontent.com/microsoft/mdatp-xplat/refs/heads/master/macos/mobileconfig/combined/mdatp.mobileconfig"
}

data "http" "reissue_fv" {
  url = "https://raw.githubusercontent.com/jamf/FileVault2_Scripts/refs/heads/master/reissueKey.sh"
}

data "http" "pkg_setup_manager" {
  url = "https://github.com/Jamf-Concepts/Setup-Manager/releases/download/v1.0/Setup.Manager.1.0-368.pkg"
}



##Scripts import
resource "jamfpro_script" "scripts_reissuekey" {
  name            = "Filevault 2 Key Reissue"
  script_contents = data.http.reissue_fv.response_body
  category_id     = -1
  os_requirements = ""
  priority        = "AFTER"
  info            = "Source https://github.com/jamf/FileVault2_Scripts/blob/master/reissueKey.sh"
  notes           = ""
  parameter4      = "Set organization name in pop up window" 
  parameter5      = "Failed Attempts until Stop"
  parameter6      = "Custom text for contact information." 
  parameter7      = "Custom Branding - Defaults to Self Service Icon"           
}


## Combined Config Profile with Content Filtering, Notifications, PPPC, Allowed System Extension and Managed Login items
resource "jamfpro_macos_configuration_profile_plist" "jamfpro_macos_configuration_combined" {
  name                = "Windows Defender MacOS Settings"
  description         = ""
  level               = "System"
  category_id         = -1
  redeploy_on_update  = "Newly Assigned"
  distribution_method = "Install Automatically"
  payloads            = data.http.defender_combined.response_body
  payload_validate    = false
  user_removable      = false

  scope {
    all_computers = true
    all_jss_users = false
  }
}

## Github PKG
resource "jamfpro_package" "jamfpro_package_setup_manager" {
  package_name          = "Jamf Setup Manager"                                                   
  package_file_source   = data.http.pkg_setup_manager.response_body
  category_id           = "-1"                                                    
  info                  = "Source https://github.com/Jamf-Concepts/Setup-Manager"                                                 
  priority              = 10                                                                    
  reboot_required       = false                                                                 
  fill_user_template    = false                                                                 
  fill_existing_users   = false                                                                 
  os_install            = false                                                                 
  suppress_updates      = false                                                                 
  suppress_from_dock    = false                                                                 
  suppress_eula         = false                                                                 
  suppress_registration = false                                                                 
  timeouts {
    create = "90m" 
  }
}
