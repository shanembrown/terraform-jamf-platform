
terraform {
  required_providers {
    jsc = {
      source                = "danjamf/jsctfprovider"
      configuration_aliases = ["jsc"]
    }
    jamfpro = {
      source                = "deploymenttheory/jamfpro"
      configuration_aliases = ["jpro"]
    }
    aws = {
    }
  }
}




