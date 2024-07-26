## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
    jsc = {
      source = "danjamf/jsctfprovider"
      version = "0.0.7"
    }
  }
}

resource "jsc_uemc" "jsc_uemc_initial" {
   domain       = "https://rlegg.jamfcloud.com/"
   clientid     = "5ee0c8f7-b519-44d4-ae5a-a764ac6ef784"
   clientsecret = "e899lyH7QU7Gq1HWB3FObV74IZUlgxJ-87ZpTZWNMC_zU0eMx0qn45kdDlKomOlr"
}

resource "jsc_oktaidp" "okta_idp_base" {
  clientid  = "0oa71hsl3q3umwKZz5d7"
  name      = "Okta IDP Integration"
  orgdomain = "https://dev-13925600.okta.com"
}

resource "jsc_ap" "all_services" {
    name             = "Jamf Connect ZTNA and Protect"
    oktaconnectionid = jsc_oktaidp.okta_idp_base.id
    privateaccess    = true
    threatdefence    = true
    datapolicy       = true
}

resource "jsc_blockpage" "data_block" {
    title = "Content Blocked"
    description = "This site is blocked by an administrator-defined Internet content policy. You are able to customize this policy – and even this message – in your organization's Jamf Security Cloud console."
    type = "block"
    show_requesturl = true
    show_classification = true
}

resource "jsc_blockpage" "secure_block" {
  title = "Security Risk"
  description = "This site is blocked by an administrator-defined security policy. You are able to customize this policy – and even this message – in your organization's Jamf Security Cloud console."
  type = "secureBlock"
  show_requesturl = false
  show_classification = true
}

resource "jsc_blockpage" "cap" {
  title = "Data Limit Reached"
  description = "You have reached the data limit set by your organization. You'll still be allowed use work related applications on your cellular connection but all other use will need to be on Wi-Fi."
  type = "cap"
  show_requesturl = true
  show_classification = true
}

resource "jsc_blockpage" "device_risk" {
  title = "Access Blocked Due to Device Risk"
  description = "You cannot access this site because the risk level of your device is too high. Please open the Jamf Trust app on your device to learn more."
  type = "deviceRisk"
  show_requesturl = true
  show_classification = true
}

resource "jsc_blockpage" "mangement_block" {
  title = "Un-Managed Device - Access Restricted"
  description = "You cannot access this site because your device is not managed. If you are using an un-managed device, please switch to an organizationally managed device to access this resource."
  type = "deviceManagement"
  show_requesturl = true
  show_classification = true
}

