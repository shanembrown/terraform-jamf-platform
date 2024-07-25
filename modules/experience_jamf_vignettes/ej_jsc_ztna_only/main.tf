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

resource "jsc_ap" "ZTNA Only" {
    name             = "Jamf Conenct ZTNA"
    oktaconnectionid = ""
    privateaccess    = true
    threatdefence    = false
    datapolicy       = false
}