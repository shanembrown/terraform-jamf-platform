# Jamf Platform - SaaS Tenancy Control

This vignette deploys a complete SaaS Tenancy Control module in Jamf Pro and Jamf Security Cloud.

Provider versions used in this release:

- hashicorp/aws v5.61.0
- danjamf/jsctfprovider v>= 0.0.15

## Prerequisites

More details see https://github.com/Jamf-Concepts/saastenancy

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terraform init -upgrade
```