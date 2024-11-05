/*
This terraform blueprint will build the macOS CIS Benchmark vignette from Experience Jamf.
It will do the following:
 - Create 1 category
 - Create 3 scripts
 - Create 3 extension attributes
 - Create 5 smart computer groups
 - Create 4 policies
 - Create 8 configuration profiles

 Prerequisites:
  - the Dialog tool must be installed
*/

## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.11"
    }
  }
}

resource "random_id" "entropy" {
  keepers = {
    first = "${timestamp()}"
  }
  byte_length = 1
}

## Create categories
resource "jamfpro_category" "category_cis_benchmarks" {
  name     = "Mac CIS Benchmarks [${random_id.entropy.hex}]"
  priority = 9
}

## Create script

resource "jamfpro_script" "script_sonoma_cis_lvl1_compliance" {
  name            = "Sonoma CIS Level 1 Compliance [${random_id.entropy.hex}]"
  priority        = "AFTER"
  script_contents = file("${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_scripts/sonoma_cis_lvl1_compliance.sh")
  category_id     = jamfpro_category.category_cis_benchmarks.id
  info            = "This script will apply a set of rules related to the CIS Level 1 benchmark for macOS Sonoma"
}

## Create computer extension attribute

resource "jamfpro_computer_extension_attribute" "ea_cis_failed_count" {
  name                   = "CIS - Compliance Failed Results Count [${random_id.entropy.hex}]"
  input_type             = "SCRIPT"
  enabled                = true
  data_type              = "INTEGER"
  inventory_display_type = "EXTENSION_ATTRIBUTES"
  script_contents        = file("${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_extension_attributes/cis_compliance_failed_count.sh")
}

## Create Smart Computer Groups
resource "jamfpro_smart_computer_group" "group_sonoma_computers" {
  name = "CIS - Sonoma Computers [${random_id.entropy.hex}]"
  criteria {
    name        = "Operating System Version"
    search_type = "like"
    value       = "14."
    and_or      = "and"
    priority    = 0
  }
}

resource "jamfpro_smart_computer_group" "group_sonoma_cis_lvl1_non_compliant" {
  name = "CIS Level 1 - Sonoma - Non Compliant Computers [${random_id.entropy.hex}]"
  criteria {
    name        = "Operating System Version"
    search_type = "like"
    value       = "14."
    and_or      = "and"
    priority    = 0
  }
  criteria {
    name        = jamfpro_computer_extension_attribute.ea_cis_failed_count.name
    search_type = "more than"
    value       = "0"
    and_or      = "and"
    priority    = 1
  }
}

## Create policies

resource "jamfpro_policy" "policy_sonoma_cis_lvl1_audit" {
  name            = "CIS Level 1 - Audit (Sonoma) [${random_id.entropy.hex}]"
  enabled         = true
  trigger_checkin = true
  frequency       = "Ongoing"
  category_id     = jamfpro_category.category_cis_benchmarks.id

  scope {
    all_computers      = false
    computer_group_ids = [jamfpro_smart_computer_group.group_sonoma_computers.id]
  }

  self_service {
    use_for_self_service = false
  }

  payloads {
    scripts {
      id         = jamfpro_script.script_sonoma_cis_lvl1_compliance.id
      parameter4 = "--check"
    }

    maintenance {
      recon = true
    }

    reboot {
      file_vault_2_reboot            = false
      message                        = "This computer will restart in 5 minutes. Please save anything you are working on and log out by choosing Log Out from the bottom of the Apple menu."
      minutes_until_reboot           = 5
      no_user_logged_in              = "Do not restart"
      start_reboot_timer_immediately = false
      startup_disk                   = "Current Startup Disk"
      user_logged_in                 = "Do not restart"
    }
  }
}

resource "jamfpro_policy" "policy_sonoma_cis_lvl1_remediation" {
  name            = "CIS Level 1 - Remediation (Sonoma) [${random_id.entropy.hex}]"
  enabled         = true
  trigger_checkin = true
  frequency       = "Ongoing"
  category_id     = jamfpro_category.category_cis_benchmarks.id

  scope {
    all_computers      = false
    computer_group_ids = [jamfpro_smart_computer_group.group_sonoma_cis_lvl1_non_compliant.id]
  }

  self_service {
    use_for_self_service = false
  }

  payloads {
    scripts {
      id         = jamfpro_script.script_sonoma_cis_lvl1_compliance.id
      parameter4 = "--check"
      parameter5 = "--fix"
      parameter6 = "--check"
    }

    maintenance {
      recon = true
    }

    reboot {
      file_vault_2_reboot            = false
      message                        = "This computer will restart in 5 minutes. Please save anything you are working on and log out by choosing Log Out from the bottom of the Apple menu."
      minutes_until_reboot           = 5
      no_user_logged_in              = "Do not restart"
      start_reboot_timer_immediately = false
      startup_disk                   = "Current Startup Disk"
      user_logged_in                 = "Do not restart"
    }
  }
}

## Define configuration profile details
locals {
  cis_lvl1_macos_14_dict = {
    "Application Access"    = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-applicationaccess.mobileconfig"
    "Login Window"          = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-loginwindow.mobileconfig"
    "Managed Client"        = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-timed.mobileconfig"
    "MCX"                   = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-mcx.mobileconfig"
    "Safari"                = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-safari.mobileconfig"
    "Screen Saver"          = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-screensaver.mobileconfig"
    "System Policy Control" = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-systempolicy.control.mobileconfig"
    "Terminal"              = "${var.support_files_path_prefix}modules/trusted_access_outcomes/mac_cis_benchmark_tailored/support_files/computer_config_profiles/sonoma_cis_lvl1-terminal.mobileconfig"
  }
}

## Create configuration profiles
resource "jamfpro_macos_configuration_profile_plist" "sonoma_cis_lvl1" {
  for_each            = local.cis_lvl1_macos_14_dict
  name                = "Sonoma_cis_lvl1 - ${each.key} [${random_id.entropy.hex}]"
  distribution_method = "Install Automatically"
  redeploy_on_update  = "Newly Assigned"
  category_id         = jamfpro_category.category_cis_benchmarks.id
  level               = "System"

  payloads = file("${each.value}")

  scope {
    all_computers      = false
    computer_group_ids = [jamfpro_smart_computer_group.group_sonoma_computers.id]
  }
}
