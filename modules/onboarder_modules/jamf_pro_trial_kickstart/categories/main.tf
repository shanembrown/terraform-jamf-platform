## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}


## Categories not specific to an "outcome". If relative to an outcome the category is created in the specific outcome module

resource "random_id" "entropy" {
  keepers = {
    first = "${timestamp()}"
  }
  byte_length = 1
}

## Create Categories

resource "jamfpro_category" "category_communication" {
  name     = "Communication [${random_id.entropy.hex}]"
  priority = 9
}

resource "jamfpro_category" "category_developer_tools" {
  name     = "Developer Tools [${random_id.entropy.hex}]"
  priority = 9
}

resource "jamfpro_category" "category_network" {
  name     = "Network Security [${random_id.entropy.hex}]"
  priority = 9
}

resource "jamfpro_category" "category_printers" {
  name     = "Printers [${random_id.entropy.hex}]"
  priority = 9
}

resource "jamfpro_category" "category_productivity" {
  name     = "Productivity [${random_id.entropy.hex}]"
  priority = 9
}

resource "jamfpro_category" "category_security_compliance" {
  name     = "Security and Compliance [${random_id.entropy.hex}]"
  priority = 9
}

resource "jamfpro_category" "category_uninstallers" {
  name     = "Uninstallers [${random_id.entropy.hex}]"
  priority = 9
}
