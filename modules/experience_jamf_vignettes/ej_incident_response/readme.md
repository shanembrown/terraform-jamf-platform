# EJ-Terraform - Incident Response Vignette

Terraform vignette for the "Experience Jamf (EJ)" environment. This vignette deploys a complete Incident & Response module in Jamf Pro using the Aftermath tool.

Provider versions used in this release:

- deploymenttheory/jamfpro v0.1.5
- danjamf/jsctfprovider v0.0.11

## Prerequisites

No prerequisites required

## Deploy this module

Create a terraform.tfvars in the root folder and set the following knob to true:

```
include_ej_incident_response = true
```

Then run the following commands:

```
terraform init
terraform plan
terraform apply
```

