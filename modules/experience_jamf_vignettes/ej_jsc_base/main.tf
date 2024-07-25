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

resource "jsc_uemc" "jsc_uemc_initial" {
  domain = "https://rlegg.jamfcloud.com"
  clientid = "5522111b-53bf-447b-ac95-69404fc641d4"
  clientsecret = "uDc3h2WST7p65jnlrUcCHMI6m1oPy6qt_3G_G0n4Y-YuvTjyo9gSaKyFP0w3ixKg"
}

