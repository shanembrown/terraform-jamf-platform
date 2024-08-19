output "jsc_ap_id" {
  value = resource.jsc_ap.all_services.id
}

output "jsc_ap_appconfig" {
    value = resource.jsc_ap.all_services.supervisedappconfig
}