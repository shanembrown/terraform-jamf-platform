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

resource "jsc_ap" "ztna_only" {
    name = "Connect ZTNA"
    oktaconnectionid = var.jsc_provided_idp_client
    privateaccess    = true
    datapolicy       = false
    threatdefence    = false  
}