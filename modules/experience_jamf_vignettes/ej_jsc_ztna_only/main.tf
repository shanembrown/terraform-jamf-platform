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
    oktaconnectionid = "66a2b81cd3698b6cb78d21af"
    privateaccess    = true
    datapolicy       = false
    threatdefence    = false  
}