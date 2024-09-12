## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
    jsc = {
      source = "jsctf"
    }
  }
}

provider "jsc" {
  username = "ryan.legg+local@jamf.com"
  password = "Tw1ster8923"
}

resource "jsc_oktaidp" "okta_idp_base" {
  clientid  = var.tje_okta_clientid
  name      = "Okta IDP Integration"
  orgdomain = var.tje_okta_orgdomain
}

resource "jsc_ap" "networkrelay" {
  name             = "Network Relay"
  oktaconnectionid = jsc_oktaidp.okta_idp_base.id
  networkrelay     = true
  privateaccess    = false
  threatdefence    = false
  datapolicy       = false
}