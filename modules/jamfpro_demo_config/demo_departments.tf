resource "jamfpro_department" "department_executives" {
  count = var.include_jamfpro_departments == "true" ? 1 : 0
  name = "Executives"
}

resource "jamfpro_department" "department_sales" {
  count = var.include_jamfpro_departments == "true" ? 1 : 0
  name = "Sales"
}

resource "jamfpro_department" "department_support" {
  count = var.include_jamfpro_departments == "true" ? 1 : 0
  name = "Support"
}

resource "jamfpro_department" "department_engineering" {
  count = var.include_jamfpro_departments == "true" ? 1 : 0
  name = "Engineering"
}