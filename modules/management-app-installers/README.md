# This module requires Jamf Pro credentials

Running this will:

- Create an App Installer for the name of the variable "App Name"
- Scope that App Installer to All Managed Computers

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terraform init -upgrade
```