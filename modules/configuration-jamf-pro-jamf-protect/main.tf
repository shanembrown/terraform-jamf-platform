## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source                = "deploymenttheory/jamfpro"
      configuration_aliases = [jamfpro.jpro]
    }
  }
}

resource "jamfpro_jamf_protect" "settings" {
  protect_url  = var.jamfprotect_url
  client_id    = var.jamfprotect_clientID
  password     = var.jamfprotect_client_password
  auto_install = true

  timeouts {
    create = "90s"
  }

}
