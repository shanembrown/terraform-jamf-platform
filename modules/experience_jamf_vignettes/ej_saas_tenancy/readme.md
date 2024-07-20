# EJ-Terraform - SaaS Tenancy Control

Terraform vignette for the "Experience Jamf (EJ)" environment. This vignette deploys a complete SaaS Tenancy Control module in Jamf Pro.

Provider versions used in this release:

- deploymenttheory/jamfpro v0.1.5
- danjamf/jsctfprovider v0.0.5

## Prerequisites

TBD

## Deploy this module

Create a terraform.tfvars in the root folder and set the following knob to true:

```
include_ej_saas_tenancy = true
```

Then run the following commands:

```
terraform init
terraform plan
terraform apply
```

