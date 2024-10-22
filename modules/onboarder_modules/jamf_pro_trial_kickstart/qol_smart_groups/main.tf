## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}

## Create Smart Computer Groups - Quality Of Life
resource "jamfpro_smart_computer_group" "group_sonoma_computers" {
  name = "* Sonoma Macs"
  criteria {
    name        = "Operating System Version"
    search_type = "like"
    value       = "14."
    and_or      = "and"
    priority    = 0
  }
}

resource "jamfpro_smart_computer_group" "group_sequoia_computers" {
  name = "* Sequoia Macs"
  criteria {
    name        = "Operating System Version"
    search_type = "like"
    value       = "15."
    and_or      = "and"
    priority    = 0
  }
}

resource "jamfpro_smart_computer_group" "group_last_checkin" {
  name = "* 7 Days Since Last Check-In"
  criteria {
    name        = "Last Check-in"
    search_type = "more than x days ago"
    value       = "7"
    and_or      = "and"
    priority    = 0
  }
}

resource "jamfpro_smart_computer_group" "group_disk_encrypted" {
  name = "* FileVault 2 Enabled"
  criteria {
    name        = "FileVault 2 Partition Encryption State"
    search_type = "is"
    value       = "Encrypted"
    and_or      = "and"
    priority    = 0
  }
}

resource "jamfpro_smart_computer_group" "group_available_swu" {
  name = "* Available Software Updates"
  criteria {
    name        = "Number of Available Updates"
    search_type = "more than"
    value       = "0"
    and_or      = "and"
    priority    = 0
  }
}