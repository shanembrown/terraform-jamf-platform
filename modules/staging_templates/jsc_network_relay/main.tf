## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
    /* jsc = {
      source  = "danjamf/jsctfprovider"
      version = ">= 0.0.15"
    } */
    jsc = {
      source = "jsctf"
    }
  }
}

provider "jsc" {
  username = "ryan.legg+local@jamf.com"
  password = "Tw1ster8923"
}

resource "jsc_ap" "networkrelay" {
  name             = "Network Relay"
  idptype          = "NetworkRelay"
  privateaccess    = true
}



resource "jamfpro_macos_configuration_profile_plist" "network_relay_macos" {
  name                = "Network Relay - macOS"
  distribution_method = "Install Automatically"
  redeploy_on_update  = "Newly Assigned"
  level               = "System"

  payloads         = jsc_ap.networkrelay.macosplist
  payload_validate = false

  scope {
    all_computers      = false
    
  }

  depends_on = [jamfpro_smart_computer_group.group_macOS_14]
}