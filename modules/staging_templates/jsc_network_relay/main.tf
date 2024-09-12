## Call Terraform provider
/* terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
      jsc = {
      source  = "jsctf"
    }
  }
}

provider "jsc" {
  username = "ryan.legg+local@jamf.com"
  password = "Tw1ster8923"
}

resource "jsc_ap" "network_relay" {
  name             = "Network Relay"
  networkrelay     = true
  privateaccess    = false
  threatdefence    = false
  datapolicy       = false
}
*/