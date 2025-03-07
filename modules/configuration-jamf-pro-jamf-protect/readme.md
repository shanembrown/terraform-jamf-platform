This module uses bash scripts and other Terraform resources to create Jamf Protect (for macOS)'s integration with Jamf Pro

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terraform init -upgrade
```