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
  clientid   = var.tje_okta_clientid
  name       = "Okta IDP Integration"
  orgdomain  = var.tje_okta_orgdomain
}

resource "jsc_ap" "content_filtering_only" {
  name             = "Content Filtering"
  oktaconnectionid = jsc_oktaidp.okta_idp_base.id
  privateaccess    = false
  threatdefence    = false
  datapolicy       = true
}

