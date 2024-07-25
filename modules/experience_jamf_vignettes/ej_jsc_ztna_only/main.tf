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
    name             = "Jamf Connect ZTNA"
    oktaconnectionid = "66a2acb005cb1b0b0929295b"
    privateaccess    = false
    threatdefence    = true
    datapolicy       = false
}