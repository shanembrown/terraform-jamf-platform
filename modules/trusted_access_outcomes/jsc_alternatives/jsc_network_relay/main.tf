## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
    jsc = {
      source  = "danjamf/jsctfprovider"
      version = ">= 0.0.15"
    }
  }
}

provider "jsc" {
  username            = "ryan.legg+local@jamf.com"
  password            = "Tw1ster8923"
  customerid          = "66a2b81cd3698b6cb78d21af"
}

provider "jamfpro" {
  jamfpro_instance_fqdn  = "https://rlegg.jamfcloud.com"
  auth_method   = "oauth2" ## oauth2 or basic
  client_id     = "5ee0c8f7-b519-44d4-ae5a-a764ac6ef784"
  client_secret = "e899lyH7QU7Gq1HWB3FObV74IZUlgxJ-87ZpTZWNMC_zU0eMx0qn45kdDlKomOlr"
}

# resource "jsc_ap" "networkrelay" {
#   name    = "Network Relay"
#   idptype = "NetworkRelay"
# }

# resource "jsc_oktaidp" "okta_idp_base" {
#   clientid  = "0oa71hsl3q3umwKZz5d7"
#   name      = "Okta IDP Integration"
#   orgdomain = var.tje_okta_orgdomain
# }

resource "jsc_ap" "networkrelay" {
  name             = "Network Relay - Testing"
  idptype          = "none"
  # oktaconnectionid = jsc_oktaidp.okta_idp_base.id
  # networkrelay     = true
}

resource "jamfpro_macos_configuration_profile_plist" "network_relay_macos" {
  name                = "Network Relay - macOS (Supervised)"
  distribution_method = "Install Automatically"
  redeploy_on_update  = "Newly Assigned"
  level               = "System"

  payloads         = jsc_ap.networkrelay.macosplist
  payload_validate = false

  scope {
    all_computers = false
  }
  # depends_on = [jsc_ap.networkrelay]
}

output "enable_jsc_uemc_output" {
  value = "yes"
}