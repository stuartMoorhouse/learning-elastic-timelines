data "ec_stack" "main" {
  version_regex = var.elastic_version
  region        = var.ec_region
}

# ec_deployment takes 4-5 minutes. If Terraform times out, follow the timeout
# handling rules in CLAUDE.md. Never re-apply blindly (duplicate clusters).
resource "ec_deployment" "main" {
  name                   = "${var.prefix}-deployment"
  region                 = var.ec_region
  version                = data.ec_stack.main.version
  deployment_template_id = var.ec_deployment_template_id

  elasticsearch = {
    hot = {
      size        = "15g"
      zone_count  = 1
      autoscaling = {}
    }

    ml = {
      size        = "8g"
      zone_count  = 1
      autoscaling = {}
    }
  }

  kibana = {
    size       = "8g"
    zone_count = 1
  }

  # Provides Fleet Server for the Elastic Agent on the VM.
  integrations_server = {}

  tags = local.ec_tags
}
