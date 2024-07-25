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
    name             = "Jamf Conenct ZTNA"
    oktaconnectionid = "0oa71hsl3q3umwKZz5d7"
    privateaccess    = true
    threatdefence    = false
    datapolicy       = false
}