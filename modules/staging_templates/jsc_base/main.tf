## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
    jsc = {
      source = "danjamf/jsctfprovider"
      version = "0.0.11"
    }
  }
}

resource "jsc_uemc" "jsc_uemc_initial" {
   domain       = var.jamfpro_instance_url
   clientid     = var.clientid
   clientsecret = var.clientsecret
}

resource "jsc_oktaidp" "okta_idp_base" {
  clientid  = var.tje_okta_clientid
  name      = "Okta IDP Integration"
  orgdomain = var.tje_okta_orgdomain
}