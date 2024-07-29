/*
This terraform blueprint will build the SaaS Tenancy Control vignette from Experience Jamf.
It will do the following:
 - 

 Prerequisites:
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
resource "jamfpro_category" "category_cis_benchmarks" {
  name     = "${var.prefix}SaaS Tenancy Control"
  priority = 9
}
