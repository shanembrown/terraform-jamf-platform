## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = "~> 0.1.5"
    }
  }
}

## Deploy demo policy
resource "jamfpro_policy" "policy_demo" {
  name                          = "demo policy"
  enabled                       = true
  trigger_enrollment_complete   = true
  frequency                     = "Once per computer"
  target_drive                  = "/"

  scope {
    all_computers = true
  }

  payloads {
    maintenance {
      recon = true
    }
  }
}