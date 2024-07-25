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

resource "jsc_oktaidp" "okta_idp" {
  clientid  = "0oa71hsl3q3umwKZz5d7"
  name      = "okta idp"
  orgdomain = "https://dev-13925600.okta.com"
}