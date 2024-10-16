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

resource "jsc_oktaidp" "okta_idp_base" {
  clientid  = var.tje_okta_clientid
  name      = "Okta IDP Integration"
  orgdomain = var.tje_okta_orgdomain
}

resource "jsc_ap" "all_services" {
  name             = "Jamf Connect ZTNA and Protect"
  idptype          = "OKTA"
  oktaconnectionid = jsc_oktaidp.okta_idp_base.id
  privateaccess    = true
  threatdefence    = true
  datapolicy       = true
}

resource "jamfpro_macos_configuration_profile_plist" "all_services_macos" {
  name                = "Jamf Connect ZTNA + Jamf Protect Threat and Content Control - macOS (Supervised)"
  distribution_method = "Install Automatically"
  redeploy_on_update  = "Newly Assigned"
  level               = "System"

  payloads         = jsc_ap.all_services.macosplist
  payload_validate = false

  scope {
    all_computers = false
  }
  depends_on = [jsc_ap.all_services]
}

resource "jamfpro_smart_mobile_device_group" "supervised_ios" {
  name = "Jamf Security Cloud - Supervised Devices"

  criteria {
    name = "Supervised"
    priority = 0
    search_type = "is"
    value = "Supervised"
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "all_services_ios_supervised" {
  name = "Jamf Connect ZTNA + Jamf Protect Threat and Content Control - iOS / iPadOS (Supervised)"
  redeploy_on_update = "Newly Assigned"
  
  payloads = jsc_ap.all_services.supervisedplist
  payload_validate = false

  scope {
    all_mobile_devices = false
  }
  depends_on = [ jamfpro_macos_configuration_profile_plist.all_services_macos ]
}

resource "jamfpro_smart_mobile_device_group" "unsupervised_ios" {
  name = "Jamf Security Cloud - Un-Supervised Devices"

  criteria {
    name = "Supervised"
    priority = 0
    search_type = "is"
    value = "Unsupervised"
  }
}

resource "jamfpro_mobile_device_configuration_profile_plist" "all_services_ios_unsupervised" {
  name = "Jamf Connect ZTNA + Jamf Protect Threat and Content Control - iOS / iPadOS (Un-Supervised)"
  redeploy_on_update = "Newly Assigned"
  
  payloads = jsc_ap.all_services.unsupervisedplist
  payload_validate = false

  scope {
    all_mobile_devices = false
  }
  depends_on = [ jamfpro_mobile_device_configuration_profile_plist.all_services_ios_supervised ]
}

output "enable_jsc_uemc_output" {
  value = true
}