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

resource "jsc_uemc" "jsc_uemc_initial" {
    clientid     = var.jamfpro_client_id
    clientsecret = var.jamfpro_client_secret
    domain       = var.jamfpro_instance_url
}

