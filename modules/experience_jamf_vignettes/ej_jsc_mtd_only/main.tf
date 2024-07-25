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

resource "jsc_ap" "mtd_only" {
    name             = "Mobile Threat Defense"
    oktaconnectionid = ""
    privateaccess    = false
    threatdefence    = true
    datapolicy       = false
}