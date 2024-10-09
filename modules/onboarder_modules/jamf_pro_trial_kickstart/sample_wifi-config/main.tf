## Sample buildings, categories, departments and smart groups - not tied to any modules. More for examples during trials


## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}

#Buildings

resource "jamfpro_building" "building_headquarters" {
  name    = "Headquarters"
  city    = "Minneapolis"
  country = "USA"
}

resource "jamfpro_building" "building_tokyo" {
  name       = "Tokyo Office"
  city       = "Tokyo"
  country    = "Japan"
  depends_on = [jamfpro_building.building_headquarters]
}