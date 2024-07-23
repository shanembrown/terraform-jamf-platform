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

## Create categories
resource "jsctfprovider_ap" "myaptest" {
    name          = "Test Activation Profile"
    threatdefense = true
    datapolicy    = true
}