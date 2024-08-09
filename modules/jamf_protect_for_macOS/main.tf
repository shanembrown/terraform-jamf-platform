# Define a resource to use the local-exec provisioner
resource "null_resource" "run_script" {
  # Use a provisioner to execute the local script
  provisioner "local-exec" {
    # Pass the variable as a command line argument to the script
    command = "${path.module}/protectintegrationcreate.sh ${var.jamfpro_instance_url} ${var.jamfpro_client_id} ${var.jamfpro_client_secret} ${var.jamfprotect_url} ${var.jamfprotect_clientID} ${var.jamfprotect_client_password}"
    when    = create
  }

  # Provisioner to run the script during destruction - TO DO add self variables
  provisioner "local-exec" {
    command = "${path.module}/protectintegrationdelete.sh"
    when    = destroy
  }
}
