/*
This terraform blueprint will build the macOS CIS Benchmark vignette from Experience Jamf.
It will do the following:
 - Create categories
 - Create configuration profiles
*/

## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
  }
}

## Create categories
resource "jamfpro_category" "category_cis1_ventura" {
  name     = "Ventura_cis_lvl1"
  priority = 9
}

resource "jamfpro_category" "category_cis1_sonoma" {
  name     = "Sonoma_cis_lvl1"
  priority = 9
}

## Define configuration profile details
locals {
  profile_plist_regex     = "(<plist.+?>\\s)([\\s\\S]+?)(\\s<\\/plist>)"

  cis_lvl1_macos_14_dict = {
    "Application Access"    = "support_files/computer_config_profiles/sonoma_cis_lvl1-applicationaccess.mobileconfig"
    "Login Window"          = "support_files/computer_config_profiles/sonoma_cis_lvl1-loginwindow.mobileconfig"
    "Managed Client"        = "support_files/computer_config_profiles/sonoma_cis_lvl1-timed.mobileconfig"
    "MCX"                   = "support_files/computer_config_profiles/sonoma_cis_lvl1-mcx.mobileconfig"
    "Safari"                = "support_files/computer_config_profiles/sonoma_cis_lvl1-safari.mobileconfig"
    "Screen Saver"          = "support_files/computer_config_profiles/sonoma_cis_lvl1-screensaver.mobileconfig"
    "System Policy Control" = "support_files/computer_config_profiles/sonoma_cis_lvl1-systempolicy.control.mobileconfig"
    "Terminal"              = "support_files/computer_config_profiles/sonoma_cis_lvl1-terminal.mobileconfig"
  }
}

## Create configuration profiles
resource "jamfpro_macos_configuration_profile_plist" "sonoma_cis_lvl1" {
  for_each    = local.cis_lvl1_macos_14_dict
  name        = "Sonoma_cis_lvl1 - ${each.key}"
  distribution_method = "Install Automatically"
  redeploy_on_update = "Newly Assigned"
  category_id = jamfpro_category.category_cis1_sonoma.id
  level = "System"

  payloads = file("${each.value}")

  scope {
    all_computers = true
  }
}