/*
resource "jsc_oktaidp" "tje_okta_config" {
  name = "TJE ${var.wizard_suffix} ${random_string.random.result}"
  orgdomain = var.tje_okta_orgdomain
  clientid = var.tje_okta_clientid
}

resource "jsc_uemc" "my_uemc_config" {
  count = var.radar_user != "empty" ? 1 : 0
  domain       = var.jamfpro_instance_url
  clientid     = data.jamfpro_api_integration.jamfpro_api_client_idandsecret.client_id
  clientsecret = data.jamfpro_api_integration.jamfpro_api_client_idandsecret.client_secret
}
*/