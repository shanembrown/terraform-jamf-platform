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

resource "jsc_ap" "all_services" {
    name             = "Jamf Connect ZTNA and Protect"
    oktaconnectionid = "Okta SSO"
    privateaccess    = true
    threatdefence    = true
    datapolicy       = true
}