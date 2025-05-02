
terraform {
  required_providers {
    jsc = {
      source                = "danjamf/jsctfprovider"
      configuration_aliases = [jsc.jsc]
    }
    jamfpro = {
      source                = "deploymenttheory/jamfpro"
      configuration_aliases = [jamfpro.jpro]
    }
    aws = {
    }
  }
}




