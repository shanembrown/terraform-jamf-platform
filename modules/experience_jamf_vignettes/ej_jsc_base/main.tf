## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
    jsc = {
      source = "danjamf/jsctfprovider"
      version = "0.0.5"
    }
  }
}

resource "jsc_oktaidp" "okta" {
  clientid  = "0oa1qa4x0qj2Jzeco1d8"
  name      = "Okta IdP"
  orgdomain = "jamf-harbor.okta.com"
}

resource "jsc_uemc" "pro_uemc" {
  domain       = var.jamfpro_instance_url
  clientid     = var.jamfpro_client_id
  clientsecret = var.jamfpro_client_secret
}