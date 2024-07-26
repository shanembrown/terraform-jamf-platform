## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
    jsc = {
      source = "danjamf/jsctfprovider"
      version = "0.0.6"
    }
  }
}

resource "jsc_ztna" "jsc_dropbox" {
  name = "Dropbox"
  routeid = "a7d2"
  hostnames = ["*dropbox.com", "*.dropbox.com"]
}