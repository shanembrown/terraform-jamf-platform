## Call Terraform provider
terraform {
  required_providers {
    jamfpro = {
      source  = "deploymenttheory/jamfpro"
      version = ">= 0.1.5"
    }
  }
}

resource "jamfpro_app_installer" "app" {
  name            = var.app_name
  enabled         = var.enabled
  deployment_type = var.deployment_type
  update_behavior = var.update_behavior
  category_id     = "-1"
  site_id         = "-1"
  smart_group_id  = "1"

  install_predefined_config_profiles = true
  trigger_admin_notifications        = var.trigger_admin_notifications

  notification_settings {
    notification_message  = "A new ${var.app_name} update is available"
    notification_interval = 1
    deadline_message      = "Update deadline approaching"
    deadline              = var.deadline
    quit_delay            = var.quit_delay
    complete_message      = "Update completed successfully"
    relaunch              = true
    suppress              = false
  }

  self_service_settings {
    include_in_featured_category   = true
    include_in_compliance_category = false
    force_view_description         = false
    description                    = "${var.app_name} is an App provided from your Self Service Provider."
  }
}
