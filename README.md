# EJ-Terraform

Terraform configuration for the "Experience Jamf (EJ)" environment.

Provider versions used in this release:

- deploymenttheory/jamfpro > = v0.2.0
- danjamf/jsctfprovider >= v0.0.15
- hasicorp/aws v55.62.0 (optional with SaaS tenancy control)

This project utlizes the unoffical Terraform providers for [Jamf Pro](https://registry.terraform.io/providers/deploymenttheory/jamfpro/latest) and [Jamf Security Cloud](https://registry.terraform.io/providers/danjamf/jsctfprovider/latest)

## Prerequisites

While this project is private, you'll need to authenticate against GitHub to clone this repository. We advise you generate a Personal Access Token (PAT) in GitHub settings. Once done, you can follow the commands below.

## Project Initialization

Open a Terminal window and enter the following commands. Replace the following placeholders:

- [BRANCH-NAME]: The name of the branch to clone (typically should clone from staging unless specifcally looking to add onto another branch before it goes to staging)
- [PAT]: Your Personal Access Token (you may receive additional SSO login prompts upon first use)
- [FIRST.LAST]: Your local user directory

```
git clone -b [BRANCH-NAME] https://[PAT]@github.com/jamf/ExperienceJamf-Terraform.git /Users/[FIRST.LAST]/ExperienceJamf-Terraform/
cd /Users/[FIRST.LAST]/ExperienceJamf-Terraform
terraform init
```

## Parallelism and API delay

This project running a big amount of API commands to create a full Jamf Pro configuration, some testings indicate that lowering Terraform parallelism from 10 to 1 reduces the chances of API call errors. Run this command before applying your configuration

```
export TF_CLI_ARGS_apply="-parallelism=1"
```

We also recommend setting the `mandatory_request_delay_milliseconds`provider key to 100.

## Variables definition

This Terraform project requires Jamf API credentials and other context-specific variables that you'll need to define locally in a terraform.tfvars file.

```
cd /Users/[FIRST.LAST]/ExperienceJamf-Terraform
nano terraform.tfvars
```

Copy and paste the following data then customize it with your own credentials and set knobs to enable specific modules contained within this project. 

```
## Jamf Pro Account Details
jamfpro_instance_url  = ""
jamfpro_auth_method   = "" ## oauth2 or basic
jamfpro_client_id     = ""
jamfpro_client_secret = ""
jamfpro_username      = ""
jamfpro_password      = ""

## Jamf Protect Account Details
jamfprotect_url             = ""
jamfprotect_clientID        = ""
jamfprotect_client_password = ""

## Jamf Security Cloud (RADAR) Account Details
jsc_username            = ""
jsc_password            = ""
tje_okta_clientid       = ""
tje_okta_orgdomain      = ""
block_page_logo         = "" ## block_page_logo takes a Base 64 encoded string conversion of the image only

### SaaS Tenancy
include_ej_saas_tenancy = false
VPCId                   = ""
KeyName                 = ""
SubnetId                = ""
aws_region              = ""

# File path prefix for Terraform directory
support_files_path_prefix = "" ## Path to your directory - example: /Users/<youruser>/filename/

##################################
##### ONBOARDER MODULE KNOBS #####
##################################


## Jamf Pro Knobs ##
include_qol_smart_groups             = false
include_categories                   = false
include_computer_management_settings = false
include_mobile_device_kickstart      = false

## (Pro) Compliance Benchmark Knobs
include_mac_cis_lvl1_benchmark    = false
include_mobile_cis_lvl1_benchmark = false
include_mac_stig_benchmark        = false
include_mobile_stig_benchmark     = false
include_mac_800_171_benchmark     = false
include_mac_cmmc_lvl1_benchmark   = false

## (Pro) Outcome Knobs
include_microsoft_365          = false
include_filevault              = false
include_rosetta                = false
include_passwordless_ssoe      = false
include_admin_tools            = false ## Pending build
include_jc_privilege_elevation = false ## Pending build

## (Pro) App Installer Knobs
include_google_chrome   = false
include_mozilla_firefox = false
include_slack           = false
include_dropbox         = false
include_google_drive    = false
include_jamf_composer   = false
include_pppc_utility    = false
include_jamfcheck       = false
include_zoom            = false

## Jamf Protect Knobs ##
include_jamf_protect_trial_kickstart = false

## Jamf Security Cloud Knobs ##
include_jsc_block_pages   = false
include_jsc_all_services  = false
include_jsc_uemc          = false

############################################

##################################
##### MISC MODULE KNOBS ##########
##################################

##### NOT INCLUDED IN ONBORDER ###

## Jamf Security Cloud Knobs ##
include_jsc_dp_only       = false
include_jsc_mtd_only      = false
include_jsc_ztna          = false
include_jsc_network_relay = false
include_jsc_mtd_dp_only   = false
include_jsc_ztna_dp_only  = false
include_jsc_ztna_mtd_only = false

## Experience Jamf Knobs ##
include_ej_base                 = false
include_ej_incident_response    = false
include_ej_mac_cis_benchmark    = false
include_ej_mobile_cis_benchmark = false
include_ej_jsc_config           = false
include_ej_mac_LMAM             = false

```

Save and exit.

## Usage

Ensure that you are in the correct project folder when performing Terraform commands, ie.,

```
/Users/[FIRST.LAST]/ExperienceJamf-Terraform/
```

Before applying any terraform modules you must initialize the providers being called. It's a good idea to run this before the first apply of your session

```
terrafrom init -upgrade
```

Terraform must be formatted correctly to run, which can be done manually after saving changes before each run with `terraform fmt`. If using Visual Studio Code, use [this guide](https://medium.com/nerd-for-tech/how-to-auto-format-hcl-terraform-code-in-visual-studio-code-6fa0e7afbb5e) to never have to run the format command again!

Enter the following command to apply full Terraform config:

```
terraform apply
```

Enter this command to only apply specific modules:

```
terraform apply -target "module.[MODULE_NAME]"
```

By default all modules will be applied. You can unselect individual modules by modifing the module knobs in your tfvars file e.g.

```
include_ej_mac_cis_benchmark = false
```

## Modules

Each module can be applied individually to test EJ vignettes:

- module.ej_base
- module.ej_incident_response
- module.ej_mac_cis_benchmark
- module.ej_mobile_cis_benchmark
- module.ej_secure_remote_access

Other modules are also available for more general purpose:

- module.jamfpro_demo_config
- module.jsc_demo_config

Want to experiment with your own config? Use this module:

- module.sandbox