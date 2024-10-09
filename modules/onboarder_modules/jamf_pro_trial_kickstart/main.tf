## Sample buildings, categories, departments and smart groups - not tied to any modules. More for examples during trials


## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}

# #Buildings

resource "jamfpro_building" "building_headquarters" {
  name    = "Headquarters"
  city    = "Minneapolis"
  country = "USA"
}

resource "jamfpro_building" "building_tokyo" {
  name       = "Tokyo Office"
  city       = "Tokyo"
  country    = "Japan"
  depends_on = [jamfpro_building.building_headquarters]
}

resource "jamfpro_building" "building_london" {
  name       = "London Office"
  city       = "London"
  country    = "UK"
  depends_on = [jamfpro_building.building_tokyo]
}

resource "jamfpro_building" "building_paris" {
  name       = "Paris Office"
  city       = "Paris"
  country    = "France"
  depends_on = [jamfpro_building.building_london]
}

#Categories

resource "jamfpro_category" "category_developer_tools" {
  name       = "Developer Tools"
  priority   = 9
  depends_on = [jamfpro_building.building_paris]
}

resource "jamfpro_category" "category_network" {
  name       = "Network Security"
  priority   = 9
  depends_on = [jamfpro_category.category_developer_tools]
}

resource "jamfpro_category" "category_printers" {
  name       = "Printers"
  priority   = 9
  depends_on = [jamfpro_category.category_network]
}

resource "jamfpro_category" "category_productivity" {
  name       = "Productivity"
  priority   = 9
  depends_on = [jamfpro_category.category_printers]
}

resource "jamfpro_category" "category_security_compliance" {
  name       = "Security and Compliance"
  priority   = 9
  depends_on = [jamfpro_category.category_productivity]
}

resource "jamfpro_category" "category_uninstallers" {
  name       = "Uninstallers"
  priority   = 9
  depends_on = [jamfpro_category.category_security_compliance]
}

#Departments

resource "jamfpro_department" "department_executives" {
  name       = "Executives"
  depends_on = [jamfpro_category.category_uninstallers]
}

resource "jamfpro_department" "department_sales" {
  name       = "Sales"
  depends_on = [jamfpro_department.department_executives]
}

resource "jamfpro_department" "department_support" {
  name       = "Support"
  depends_on = [jamfpro_department.department_sales]
}

resource "jamfpro_department" "department_engineering" {
  name       = "Engineering"
  depends_on = [jamfpro_department.department_support]
}

# Smart Groups

# OS version
# has X App/config installed?

## Create Smart Computer Groups
resource "jamfpro_smart_computer_group" "group_OS_version" {
  name = "macOS = Sequoia"

  criteria {
    name        = "Operating System Version"
    search_type = "greater than or equal"
    value       = "15"
    priority    = 0
  }
  depends_on = [jamfpro_department.department_engineering]
}