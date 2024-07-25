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
   domain       = "https://rlegg.jamfcloud.com/"
   clientid     = "5ee0c8f7-b519-44d4-ae5a-a764ac6ef784"
   clientsecret = "e899lyH7QU7Gq1HWB3FObV74IZUlgxJ-87ZpTZWNMC_zU0eMx0qn45kdDlKomOlr"
}