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

data "jsc_pag_vpnroutes" "vpn_route_nearest" {
  name = "Nearest Data Center"
}

data "jsc_pag_apptemplates" "ap_data_docusign" {
  name = "Docusign"
}

resource "jsc_pag_ztnaapp" "ap_docusign" {
  name                                             = "Docusign"
  routingtype                                      = "CUSTOM"
  routingid                                        = data.jsc_pag_vpnroutes.vpn_route_nearest.id
  routingdnstype                                   = "IPv6"
  categoryname                                     = "Business & Industry"
  securityriskcontrolenabled                       = true
  securityriskcontrolthreshold                     = "HIGH"
  securityriskcontrolnotifications                 = true
  securitydohintegrationblocking                   = true
  securitydohintegrationnotifications              = true
  securitydevicemanagementbasedaccessenabled       = true
  securitydevicemanagementbasedaccessnotifications = true
  assignmentallusers                               = true
  apptemplateid                                    = data.jsc_pag_apptemplates.ap_data_docusign.id
}
