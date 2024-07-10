/*
This terraform blueprint will build the macOS CIS Benchmark vignette from Experience Jamf.
It will do the following:
 - 
 -
 -
*/

## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
  }
}

## Create categories
resource "jamfpro_category" "category_cis1_ventura" {
  name     = "Ventura_cis_lvl1"
  priority = 9
}

resource "jamfpro_category" "category_cis1_sonoma" {
  name     = "Sonoma_cis_lvl1"
  priority = 9
}

