# HashiCorp Mesh Terraform Module

Provisions Vault policies, AppRole credentials, Transit encryption key, and Consul
service intentions for a Moltis deployment.

## Usage

```hcl
module "moltis_mesh" {
  source = "./deploy/terraform/hashicorp-mesh"

  vault_address  = "https://vault.example.com:8200"
  consul_address = "https://consul.example.com:8500"
  service_name   = "moltis-gateway"
}
```

## What this creates

| Resource | Purpose |
|----------|---------|
| `vault_policy.moltis_kv` | Read/write/list/delete secrets under the Moltis KV prefix |
| `vault_policy.moltis_transit` | Encrypt/decrypt via the Transit key (if enabled) |
| `vault_policy.moltis_token` | Token lookup-self and renew-self |
| `vault_transit_secret_backend_key.moltis` | AES-256-GCM Transit key for envelope encryption |
| `vault_approle_auth_backend_role.moltis` | AppRole role bound to the above policies |
| `vault_approle_auth_backend_role_secret_id.moltis` | Response-wrapped secret_id (5 min TTL) |
| `consul_config_entry.moltis_intentions` | Service intention allowing specified sources |

## Prerequisites

- Vault KV v2 secrets engine mounted at `var.vault_kv_mount`
- Vault Transit secrets engine mounted at `var.vault_transit_mount` (optional)
- Vault AppRole auth method enabled at `var.vault_approle_mount`
- Consul ACL system enabled

## Outputs

- `vault_role_id` — AppRole role_id (put in `moltis.toml` or env var)
- `vault_wrapped_secret_id` — Response-wrapped secret_id (unwrap once, set as env var)
- `moltis_toml_snippet` — Ready-to-paste configuration block
