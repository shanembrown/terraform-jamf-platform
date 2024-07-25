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

resource "jsc_ap" "content_filtering_only" {
    name             = "Content Filtering"
    oktaconnectionid = "0oa71hsl3q3umwKZz5d7"
    privateaccess    = false
    threatdefence    = false
    datapolicy       = true
}