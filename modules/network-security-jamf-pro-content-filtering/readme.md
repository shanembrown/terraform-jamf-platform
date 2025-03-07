**This module requires both Jamf Pro and Jamf Security Cloud credentials.**

Running this will complete the following steps:

- Create an Okta Identity Provider entry in Jamf Security Cloud
- Create an Activation Profile in Jamf Security Cloud with Content Controls enabled with the previously created Okta IDP assigned
- Collect the Activation Profile plist and create a new Configuration Profile in Jamf Pro

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terraform init -upgrade
```