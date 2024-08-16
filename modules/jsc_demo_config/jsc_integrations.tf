## IDP integration
resource "random_string" "random" {
  length           = 2
  special          = false
  override_special = "/@£$"
}

resource "jsc_oktaidp" "tje_okta_config" {
  name      = "${var.prefix}Demo Tenant - ${random_string.random.result}"
  orgdomain = var.tje_okta_orgdomain
  clientid  = var.tje_okta_clientid
}

## UEM Connect integration
resource "jamfpro_api_role" "jamfpro_api_role_sync" {
  display_name = "${var.prefix}JSC API Role Device Sync"
  privileges   = ["Read Mac Applications", "Read Mobile Devices", "Read Mobile Device Applications", "Read Smart Mobile Device Groups", "Read Static Mobile Device Groups", "Read Computers", "Read Smart Computer Groups", "Read Static Computer Groups"]
}

resource "jamfpro_api_role" "jamfpro_api_role_signalling" {
  display_name = "${var.prefix}JSC API Role Signalling"
  privileges   = ["Update Computer Extension Attributes", "Read Computer Extension Attributes", "Delete Computer Extension Attributes", "Create Computer Extension Attributes", "Read Mobile Device Extension Attributes", "Delete Mobile Device Extension Attributes", "Create Mobile Device Extension Attributes", "Update Mobile Devices", "Update Mobile Device Extension Attributes", "Update Computers", "Update User"]
}

resource "jamfpro_api_role" "jamfpro_api_role_deploy" {
  display_name = "${var.prefix}JSC API Role Deploy"
  privileges   = ["Create iOS Configuration Profiles", "Create macOS Configuration Profiles"]
}

resource "jamfpro_api_integration" "jamfpro_api_integration_jsc" {
  display_name                  = "JSC API Client"
  enabled                       = true
  access_token_lifetime_seconds = 6000
  authorization_scopes          = [jamfpro_api_role.jamfpro_api_role_sync.display_name, jamfpro_api_role.jamfpro_api_role_signalling.display_name, jamfpro_api_role.jamfpro_api_role_deploy.display_name]
}

data "jamfpro_api_integration" "jamfpro_api_client_idandsecret" {
  id = jamfpro_api_integration.jamfpro_api_integration_jsc.id
}

resource "jsc_uemc" "my_uemc_config" {
  count        = var.jsc_username != "" ? 1 : 0
  domain       = var.jamfpro_instance_url
  clientid     = data.jamfpro_api_integration.jamfpro_api_client_idandsecret.client_id
  clientsecret = data.jamfpro_api_integration.jamfpro_api_client_idandsecret.client_secret
}
