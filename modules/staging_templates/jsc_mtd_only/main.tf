## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
    jsc = {
      source  = "danjamf/jsctfprovider"
      version = ">= 0.0.15"
    }
  }
}

resource "jsc_ap" "mtd_only" {
  name          = "Mobile Threat Defense"
  idptype       = "None"
  privateaccess = false
  threatdefence = true
  datapolicy    = false
}



resource "jamfpro_macos_configuration_profile_plist" "mtd" {
  name                = "Network Threat Defense - macOS (Supervised)"
  distribution_method = "Install Automatically"
  redeploy_on_update  = "Newly Assigned"
  level               = "System"

  payloads         = jsc_ap.mtd_only.macosplist
  payload_validate = false

  scope {
    all_computers = false
  }
  depends_on = [jsc_ap.mtd_only]
}