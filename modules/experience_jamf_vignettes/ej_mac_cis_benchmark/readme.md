# EJ-Terraform - Mac CIS Benchmark Vignette

Terraform vignette for the "Experience Jamf (EJ)" environment. This vignette deploys a complete Mac CIS Benchmark module in Jamf Pro.

Provider versions used in this release:

- deploymenttheory/jamfpro v0.1.5
- danjamf/jsctfprovider v0.0.5

## Prerequisites

The Dialog tool must be already deployed on computers to display some dialogs related to this vignette

## Deploy this module

Create a terraform.tfvars in the vignette folder first. Then apply the following commands:

```
terraform init
terraform plan
terraform apply
```

