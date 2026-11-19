variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "region" {
  description = "Azure region for the VM"
  type        = string
  default     = "westeurope"
}

variable "ec_region" {
  description = "Elastic Cloud region"
  type        = string
  default     = "azure-westeurope"
}

variable "ec_deployment_template_id" {
  description = "Elastic Cloud deployment template ID. Verify it exists for the region (GET /api/v1/deployments/templates?region=<ec_region>) before apply"
  type        = string
  default     = "azure-storage-optimized"
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "elastic-timelines"
}

variable "elastic_version" {
  description = "Elastic Stack version. Also used for the Elastic Agent download on the VM"
  type        = string
  default     = "9.5.3"
}

variable "presenter_ip_cidr" {
  description = "Presenter public IP in CIDR form (e.g. 203.0.113.5/32); only source allowed for RDP"
  type        = string

  validation {
    condition     = can(cidrhost(var.presenter_ip_cidr, 0)) && var.presenter_ip_cidr != "0.0.0.0/0" && !endswith(var.presenter_ip_cidr, "/0")
    error_message = "presenter_ip_cidr must be a valid CIDR and must not be open to the internet (no /0)."
  }
}

variable "vm_size" {
  description = "Azure VM size for the Windows attack host (regular priority, never Spot)"
  type        = string
  default     = "Standard_B2ms"
}

variable "vm_admin_username" {
  description = "Windows VM admin username"
  type        = string
  default     = "demoadmin"
}

variable "tags" {
  description = "Tags applied to all Azure resources. Required by subscription policy (team, division). No default on purpose: set values in the gitignored terraform.tfvars."
  type        = map(string)
}

variable "encryption_at_host_enabled" {
  description = "Encrypt VM temp disk and caches at host. Requires the subscription feature: az feature register --namespace Microsoft.Compute --name EncryptionAtHost, then az provider register -n Microsoft.Compute"
  type        = bool
  default     = true
}

variable "atomic_red_team_ref" {
  description = "Git ref of redcanaryco/invoke-atomicredteam used for the Atomic Red Team installer on the VM"
  type        = string
  default     = "master"
}
