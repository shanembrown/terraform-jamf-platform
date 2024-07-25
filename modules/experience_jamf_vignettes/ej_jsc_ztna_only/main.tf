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

variable "okta_id" {
  type = number
  sensitive = true
  default = var.jsc_provided_idp_client
}

resource "jsc_ap" "ztna_only" {
    name             = "Jamf Connect ZTNA"
    oktaconnectionid = var.okta_id
    privateaccess    = false
    threatdefence    = true
    datapolicy       = false
}