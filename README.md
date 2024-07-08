# TJE-Terraform
Terraform configuration for The Jamf Experience (TJE) environment.

Project version 0.0.2 - 8 July 2024

Provider versions used in this release:
 - deploymenttheory/jamfpro v0.1.5
 - danjamf/jsctfprovider v0.0.5

This project utlizes the unoffical Terraform providers for [Jamf Pro](https://registry.terraform.io/providers/deploymenttheory/jamfpro/latest) and [Jamf Security Cloud](https://registry.terraform.io/providers/danjamf/jsctfprovider/latest)

## Modules
May contain modules that can be used for individual TJE vignettes.

## Prerequisites
While this project is private, you'll need to authenticate against GitHub to clone this repository. We advise you generate a Personal Access Token (PAT) in GitHub settings. Once done, you can follow the commands below.

## Project Initialization
Open a Terminal window and enter the following commands. Replace the following placeholders:
 - [BRANCH-NAME]: The name of the branch to clone (main, danwork, vincent-work, etc)
 - [PAT]: Your Personal Access Token (you may receive additional SSO login prompts upon first use)
 - [FIRST.LAST]: Your local user directory

```
git clone -b [BRANCH-NAME] https://[PAT]@github.com/jamf/TJE-Terraform.git /Users/[FIRST.LAST]/TJE-terraform/
cd /Users/[FIRST.LAST]/TJE-terraform
terraform init
```

## Variables definition
This Terraform project requires Jamf API credentials and other context-specific variables that you'll need to define locally in a terraform.tfvars file.

```
cd /Users/[FIRST.LAST]/TJE-terraform
nano terraform.tfvars
```

Copy and paste the following data then customize it with your own credentials

```
jamfpro_instance_url = "https://[MY_SERVER].jamfcloud.com"
jamfpro_client_id = ""
jamfpro_client_secret = ""
jamfpro_username = ""
jamfpro_password = ""
radar_user = ""
radar_pass = ""
```

Save and exit.

## Usage
Ensure that you are in the correct project folder when performing Terraform commands (e.g.: /Users/[FIRST.LAST]/TJE-terraform/)

```
terraform apply
```

N.b. check the optional run-list for manual configuration and clean-up that may be required
