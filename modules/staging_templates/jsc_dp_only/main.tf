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

resource "jsc_ap" "content_filtering_only" {
  name             = "Content Filtering"
  oktaconnectionid = jsc_oktaidp.okta_idp_base.id
  privateaccess    = false
  threatdefence    = false
  datapolicy       = true
}



resource "jamfpro_macos_configuration_profile_plist" "dp" {
  name                = "Content Filtering - macOS"
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
