# Fleet enrollment automation.
#
# Runs once the Elastic Cloud deployment exists: creates (or reuses) the Fleet agent policy via the
# Kibana Fleet API and resolves an enrollment token plus the real Fleet Server URL.
#
# Why not the elasticstack provider: elasticstack_fleet_agent_policy returned HTTP 404 against
# Elastic 9.5.3 (provider v0.17.0). Why not ec_deployment integrations_server.endpoints.fleet: that
# hostname differs from the one registered in /api/fleet/fleet_server_hosts.
#
# The policy is not a Terraform resource, so it has no destroy step: it goes away with the cluster
# and cannot block destroy with "Cannot delete an agent policy that is assigned to agents" (HTTP 400).
# Elastic Defend and the Windows integration are added to this policy by scripts/configure.sh.

data "external" "fleet_setup" {
  program = ["bash", "${path.module}/scripts/setup-fleet-policy.sh"]

  query = {
    kibana_url  = ec_deployment.main.kibana.https_endpoint
    username    = ec_deployment.main.elasticsearch_username
    password    = ec_deployment.main.elasticsearch_password
    policy_name = "${var.prefix}-windows-attack-vm"
  }
}

locals {
  fleet_url        = data.external.fleet_setup.result.fleet_url
  enrollment_token = sensitive(data.external.fleet_setup.result.enrollment_token)
  agent_policy_id  = data.external.fleet_setup.result.policy_id
}
