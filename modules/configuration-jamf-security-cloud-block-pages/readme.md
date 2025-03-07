**This module requires Jamf Security Cloud credentials.**

Running this will create custom Block Page entries in Jamf Security Cloud.

In their default state, they will have blocker text like "Your Text Here." You can customize this output by editing the module first in your own Branch and changing the **title** and **description** fields.

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terraform init -upgrade
```