output "elasticsearch_url" {
  description = "Elasticsearch endpoint"
  value       = ec_deployment.main.elasticsearch.https_endpoint
}

output "kibana_url" {
  description = "Kibana endpoint"
  value       = ec_deployment.main.kibana.https_endpoint
}

output "fleet_url" {
  description = "Fleet Server endpoint (not the APM endpoint)"
  value       = local.fleet_url
}

output "elastic_username" {
  description = "Elastic superuser name"
  value       = ec_deployment.main.elasticsearch_username
}

output "elastic_password" {
  description = "Elastic superuser password"
  value       = ec_deployment.main.elasticsearch_password
  sensitive   = true
}

output "agent_policy_id" {
  description = "Fleet agent policy ID for the attack VM"
  value       = local.agent_policy_id
}

output "vm_public_ip" {
  description = "Public IP of the Windows attack VM"
  value       = azurerm_public_ip.vm.ip_address
}

output "vm_name" {
  description = "Azure VM resource name"
  value       = azurerm_windows_virtual_machine.attack.name
}

output "resource_group_name" {
  description = "Azure resource group name"
  value       = azurerm_resource_group.main.name
}

output "vm_admin_username" {
  description = "Windows VM admin username"
  value       = var.vm_admin_username
}

output "rdp_command" {
  description = "Command to open an RDP session (password: terraform output -raw vm_admin_password)"
  value       = "open rdp://full%20address=s:${azurerm_public_ip.vm.ip_address}&username=s:${var.vm_admin_username}  # or: mstsc /v:${azurerm_public_ip.vm.ip_address}"
}

output "vm_admin_password" {
  description = "Windows VM admin password (generated, sensitive)"
  value       = random_password.vm_admin.result
  sensitive   = true
}
