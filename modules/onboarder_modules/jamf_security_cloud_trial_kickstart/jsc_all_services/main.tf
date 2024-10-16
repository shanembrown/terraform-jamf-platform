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

resource "jsc_oktaidp" "okta_idp_base" {
  clientid  = var.tje_okta_clientid
  name      = "Okta IDP Integration"
  orgdomain = var.tje_okta_orgdomain
}

resource "jsc_ap" "all_services" {
  name             = "Jamf Connect ZTNA and Protect"
  idptype          = "OKTA"
  oktaconnectionid = jsc_oktaidp.okta_idp_base.id
  privateaccess    = true
  threatdefence    = true
  datapolicy       = true
}

resource "jamfpro_macos_configuration_profile_plist" "dp" {
  name                = "Jamf Connect ZTNA + Jamf Protect Threat and Content Control - macOS (Supervised)"
  distribution_method = "Install Automatically"
  redeploy_on_update  = "Newly Assigned"
  level               = "System"

  payloads         = jsc_ap.all_services.macosplist
  payload_validate = false

  scope {
    all_computers = false
  }
  depends_on = [jsc_ap.all_services]
}

output "enable_jsc_uemc_output" {
  value = true
}