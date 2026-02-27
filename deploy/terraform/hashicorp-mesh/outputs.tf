# ── AppRole credentials ──────────────────────────────────────────────────────

output "vault_role_id" {
  description = "AppRole role_id for the Moltis service."
  value       = vault_approle_auth_backend_role.moltis.role_id
}

output "vault_wrapped_secret_id" {
  description = "Response-wrapped secret_id (single use, 5 min TTL). Unwrap with: vault unwrap <token>"
  value       = vault_approle_auth_backend_role_secret_id.moltis.wrapping_token
  sensitive   = true
}

# ── moltis.toml config block ────────────────────────────────────────────────

output "moltis_toml_snippet" {
  description = "Paste this into moltis.toml (replace wrapped_secret_id after unwrapping)."
  value       = <<-EOT
    [hc_vault]
    address      = "${var.vault_address}"
    auth_method  = "approle"
    role_id      = "${vault_approle_auth_backend_role.moltis.role_id}"
    secret_id    = "$${VAULT_SECRET_ID}"  # set via env var
    mount_path   = "${var.vault_kv_mount}"
    path_prefix  = "${var.vault_kv_prefix}"
    %{if var.vault_transit_mount != ""}transit_mount = "${var.vault_transit_mount}"
    %{endif}%{if var.vault_namespace != ""}namespace     = "${var.vault_namespace}"
    %{endif}# tls_ca_cert     = "/path/to/ca.pem"
    # tls_client_cert = "/path/to/client-cert.pem"
    # tls_client_key  = "/path/to/client-key.pem"

    [consul]
    address      = "${var.consul_address}"
    # token      = "$${CONSUL_HTTP_TOKEN}"
    datacenter   = "${var.consul_datacenter}"
    service_name = "${var.service_name}"
    mesh_mode    = "native"
    # tls_ca_cert     = "/path/to/consul-ca.pem"
    # tls_client_cert = "/path/to/consul-client-cert.pem"
    # tls_client_key  = "/path/to/consul-client-key.pem"
  EOT
}
