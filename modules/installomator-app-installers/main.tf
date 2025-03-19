## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.11"
    }
  }
}

resource "random_integer" "entropy" {
  min = 10
  max = 999
}

# create browsers category
resource "jamfpro_category" "category_browsers" {
  name     = "Applications"
  priority = 9
}

## Set script variable from GitHub
data "http" "script" {
  url = "https://raw.githubusercontent.com/Installomator/Installomator/refs/heads/main/Installomator.sh"
}

## Create scripts
resource "jamfpro_script" "script_installomator" {
  name            = "Installomator [${random_integer.entropy.result}]"
  priority        = var.script_priority
  script_contents = data.http.script.body
  info            = var.script_info
}

## Create policies
resource "jamfpro_policy" "policy_installomator" {
  name            = "Installomator - ${var.installomator_display_name} - Self Service [${random_integer.entropy.result}]"
  enabled         = true
  trigger_checkin = false
  frequency       = "Ongoing"

  scope {
    all_computers = true
  }

  self_service {
    use_for_self_service      = true
    self_service_display_name = var.installomator_display_name

    self_service_category {
      feature_in = false
      display_in = true
      id         = jamfpro_category.category_browsers.id
    }
  }

  payloads {
    scripts {
      id         = jamfpro_script.script_installomator.id
      parameter4 = var.installomator_label
      parameter5 = "NOTIFY=silent"
      parameter6 = "DEBUG=0"
    }

    maintenance {
      recon = true
    }

  }
}
