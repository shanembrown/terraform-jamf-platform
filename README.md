# terraform-jamf-platform

Terraform configuration for the Jamf Platform.

Provider versions used in this release:

- deploymenttheory/jamfpro > = v0.11.0
- danjamf/jsctfprovider >= v0.0.23
- hasicorp/aws v55.62.0 (optional with SaaS tenancy control)

This project utlizes the unoffical Terraform providers for [Jamf Pro](https://registry.terraform.io/providers/deploymenttheory/jamfpro/latest) and [Jamf Security Cloud](https://registry.terraform.io/providers/danjamf/jsctfprovider/latest)

## Parallelism and API delay

Lowering Terraform parallelism from 10 to 1 reduces the chances of API call errors. Run this command before applying your configuration

```
export TF_CLI_ARGS_apply="-parallelism=1"
```

We also recommend setting the `mandatory_request_delay_milliseconds`provider key to 100.

## Variables definition

This Terraform project requires Jamf API credentials and other context-specific variables that you'll need to define locally in a terraform.tfvars file.

```
cd /Users/[FIRST.LAST]/PATH
nano terraform.tfvars
```

Copy and paste the following data then customize it with your own credentials and set knobs to enable specific modules contained within this project.

```
## Jamf Pro Account Details
jamfpro_instance_url  = ""
jamfpro_auth_method   = "oauth2"
jamfpro_client_id     = ""
jamfpro_client_secret = ""


## Jamf Security Cloud (RADAR) Account Details
jsc_username          = ""
jsc_password          = ""
jsc_applicationid     = ""
jsc_applicationsecret = ""
block_page_logo       = ""
## block_page_logo takes a Base 64 encoded string conversion of the image only

## tryjamf Okta Account Details
tje_okta_clientid  = ""
tje_okta_orgdomain = ""

# File path prefix for Terraform directory
support_files_path_prefix = "" ## Path to your directory - example: /Users/<youruser>/filename/


```

Save and exit.

## Usage

Ensure that you are in the correct project folder when performing Terraform commands, ie.,

```
/Users/[FIRST.LAST]/PATH/
```

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terraform init -upgrade
```

Terraform must be formatted correctly to run, which can be done manually after saving changes before each run with `terraform fmt`. If using Visual Studio Code, use [this guide](https://medium.com/nerd-for-tech/how-to-auto-format-hcl-terraform-code-in-visual-studio-code-6fa0e7afbb5e) to never have to run the format command again!

Enter the following command, replacing the module_name with the module you intend to run. 
You can absolutely include more than one target.

```
terraform apply -target module.module_name -target module.module_name -parallelism=1
```
