locals {
  # Azure resources: the policy-required tags from var.tags plus a purpose tag.
  tags = merge(var.tags, {
    purpose = "elastic-security-timelines-demo"
  })

  # Elastic Cloud deployment: no personal or policy tags.
  ec_tags = {
    project = "learning-elastic-timelines"
    purpose = "elastic-security-timelines-demo"
  }

  apt29_script_path = "${path.module}/../scripts/vm/Invoke-APT29.ps1"

  # Written by the demo-scripts agent. Placeholder keeps validate working before it exists;
  # the VM precondition fails plan/apply if the real script is missing.
  apt29_script = try(file(local.apt29_script_path), "# placeholder: scripts/vm/Invoke-APT29.ps1 not generated yet\n")

  bootstrap_script = templatefile("${path.module}/templates/bootstrap.ps1.tftpl", {
    apt29_b64           = base64encode(local.apt29_script)
    atomic_red_team_ref = var.atomic_red_team_ref
  })
}
