# ── Providers ────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0"
    }
    consul = {
      source  = "hashicorp/consul"
      version = ">= 2.20"
    }
  }
}

# ── Vault: KV v2 policy ─────────────────────────────────────────────────────

resource "vault_policy" "moltis_kv" {
  name = "${var.service_name}-kv"

  policy = <<-EOT
    # Read/write secrets under the Moltis prefix.
    path "${var.vault_kv_mount}/data/${var.vault_kv_prefix}/*" {
      capabilities = ["create", "read", "update", "delete"]
    }

    # List secrets under the Moltis prefix.
    path "${var.vault_kv_mount}/metadata/${var.vault_kv_prefix}/*" {
      capabilities = ["list", "read"]
    }

    # Delete secret versions.
    path "${var.vault_kv_mount}/delete/${var.vault_kv_prefix}/*" {
      capabilities = ["update"]
    }
  EOT
}

# ── Vault: Transit policy ───────────────────────────────────────────────────

resource "vault_transit_secret_backend_key" "moltis" {
  count   = var.vault_transit_mount != "" ? 1 : 0
  backend = var.vault_transit_mount
  name    = var.vault_transit_key_name
  type    = "aes256-gcm96"

  deletion_allowed = false
}

resource "vault_policy" "moltis_transit" {
  count = var.vault_transit_mount != "" ? 1 : 0
  name  = "${var.service_name}-transit"

  policy = <<-EOT
    # Encrypt and decrypt with the Moltis transit key.
    path "${var.vault_transit_mount}/encrypt/${var.vault_transit_key_name}" {
      capabilities = ["update"]
    }

    path "${var.vault_transit_mount}/decrypt/${var.vault_transit_key_name}" {
      capabilities = ["update"]
    }
  EOT
}

# ── Vault: Token self-management policy ─────────────────────────────────────

resource "vault_policy" "moltis_token" {
  name = "${var.service_name}-token"

  policy = <<-EOT
    # Allow the service to look up and renew its own token.
    path "auth/token/lookup-self" {
      capabilities = ["read"]
    }

    path "auth/token/renew-self" {
      capabilities = ["update"]
    }
  EOT
}

# ── Vault: AppRole ──────────────────────────────────────────────────────────

locals {
  vault_policies = concat(
    [vault_policy.moltis_kv.name, vault_policy.moltis_token.name],
    var.vault_transit_mount != "" ? [vault_policy.moltis_transit[0].name] : [],
  )
}

resource "vault_approle_auth_backend_role" "moltis" {
  backend        = var.vault_approle_mount
  role_name      = var.service_name
  token_policies = local.vault_policies
  token_ttl      = var.vault_token_ttl
  token_max_ttl  = var.vault_token_max_ttl

  # Allow the secret_id to be used multiple times (production: set a limit).
  secret_id_num_uses = 0
}

resource "vault_approle_auth_backend_role_secret_id" "moltis" {
  backend   = var.vault_approle_mount
  role_name = vault_approle_auth_backend_role.moltis.role_name

  # Wrap the secret_id so it can only be unwrapped once.
  wrapping_ttl = "5m"
}

# ── Consul: Service intention ───────────────────────────────────────────────

resource "consul_config_entry" "moltis_intentions" {
  kind = "service-intentions"
  name = var.service_name

  config_json = jsonencode({
    Sources = [
      for src in var.consul_intention_sources : {
        Name   = src
        Action = "allow"
      }
    ]
  })
}
