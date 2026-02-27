# HashiCorp Service Mesh

Moltis integrates with HashiCorp Vault, Consul, and Nomad to provide
secret management, service discovery, mTLS, and remote sandbox execution
in enterprise environments.

## Prerequisites

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| Vault | 1.12+ | Secret storage (KV v2), envelope encryption (Transit), authentication (AppRole / K8s) |
| Consul | 1.16+ | Service registration, Connect mTLS, intention-based authorization |
| Nomad | 1.6+ (optional) | Remote sandbox execution via batch jobs |

All three are optional and independently configured. Enable only what you need.

## Configuration Reference

All HashiCorp settings live in `moltis.toml`. Values support `${ENV_VAR}` interpolation
for dynamic deployments (e.g., Terraform, Nomad templates, Kubernetes).

### Vault (`[hc_vault]`)

```toml
[hc_vault]
address      = "${VAULT_ADDR}"
auth_method  = "approle"           # "token", "approle", or "kubernetes"
role_id      = "${VAULT_ROLE_ID}"
secret_id    = "${VAULT_SECRET_ID}"
mount_path   = "secret"            # KV v2 mount (default: "secret")
path_prefix  = "moltis"            # prefix for all secrets (default: "moltis")
transit_mount = "transit"           # envelope encryption (omit to disable)
namespace    = "admin/moltis"       # Vault Enterprise namespace (omit for OSS)
tls_ca_cert     = "/etc/tls/vault-ca.pem"
tls_client_cert = "/etc/tls/vault-client.pem"
tls_client_key  = "/etc/tls/vault-client-key.pem"
```

| Field | Required | Description |
|-------|----------|-------------|
| `address` | yes | Vault server URL |
| `auth_method` | no | `"token"` (default), `"approle"`, or `"kubernetes"` |
| `token` | if token auth | Static Vault token |
| `role_id` | if approle | AppRole role ID |
| `secret_id` | if approle | AppRole secret ID |
| `role` | if kubernetes | K8s auth role name |
| `mount_path` | no | KV v2 mount (default: `"secret"`) |
| `path_prefix` | no | Secret path prefix (default: `"moltis"`) |
| `transit_mount` | no | Transit engine mount for envelope encryption |
| `namespace` | no | Vault Enterprise namespace |
| `tls_ca_cert` | no | CA certificate to verify Vault's TLS cert |
| `tls_client_cert` | no | Client certificate for mTLS to Vault |
| `tls_client_key` | no | Client private key for mTLS to Vault |

### Consul (`[consul]`)

```toml
[consul]
address              = "${CONSUL_HTTP_ADDR}"
token                = "${CONSUL_HTTP_TOKEN}"
datacenter           = "dc1"
service_name         = "moltis-gateway"
health_check_interval = 10          # seconds
mesh_mode            = "native"     # "none", "native", or "proxy"
intention_cache_ttl  = 30           # seconds
tls_ca_cert          = "/etc/tls/consul-ca.pem"
tls_client_cert      = "/etc/tls/consul-client.pem"
tls_client_key       = "/etc/tls/consul-client-key.pem"
```

| Field | Required | Description |
|-------|----------|-------------|
| `address` | no | Consul agent URL (default: `http://127.0.0.1:8500`) |
| `token` | no | Consul ACL token |
| `datacenter` | no | Datacenter name |
| `service_name` | no | Registration name (default: `"moltis-gateway"`) |
| `health_check_interval` | no | TTL check interval in seconds (default: 10) |
| `mesh_mode` | no | `"none"` (default), `"native"`, or `"proxy"` |
| `intention_cache_ttl` | no | How long to cache intention results (default: 30s) |
| `tls_ca_cert` | no | CA certificate to verify Consul's TLS cert |
| `tls_client_cert` | no | Client certificate for mTLS to Consul |
| `tls_client_key` | no | Client private key for mTLS to Consul |

### Nomad (`[nomad]`)

```toml
[nomad]
address     = "${NOMAD_ADDR}"
token       = "${NOMAD_TOKEN}"
namespace   = "default"
region      = "global"
datacenter  = "dc1"
task_driver = "docker"              # "docker" or "podman"
registry    = "registry.example.com"
job_prefix  = "moltis-sandbox"
tls_ca_cert     = "/etc/tls/nomad-ca.pem"
tls_client_cert = "/etc/tls/nomad-client.pem"
tls_client_key  = "/etc/tls/nomad-client-key.pem"
```

| Field | Required | Description |
|-------|----------|-------------|
| `address` | no | Nomad server URL (default: `http://127.0.0.1:4646`) |
| `token` | no | Nomad ACL token |
| `namespace` | no | Nomad Enterprise namespace |
| `region` | no | Nomad region |
| `datacenter` | no | Datacenter for job placement |
| `task_driver` | no | `"docker"` (default) or `"podman"` |
| `registry` | no | Container registry for sandbox images |
| `job_prefix` | no | Prefix for Nomad job IDs (default: `"moltis-sandbox"`) |
| `tls_ca_cert` | no | CA certificate to verify Nomad's TLS cert |
| `tls_client_cert` | no | Client certificate for mTLS to Nomad |
| `tls_client_key` | no | Client private key for mTLS to Nomad |

## Vault Policy Setup

Moltis needs three Vault policies. Use the Terraform module at
`deploy/terraform/hashicorp-mesh/` or create them manually:

### KV v2 Secrets

```hcl
path "secret/data/moltis/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/moltis/*" {
  capabilities = ["list", "read"]
}

path "secret/delete/moltis/*" {
  capabilities = ["update"]
}
```

### Transit Envelope Encryption

```hcl
path "transit/encrypt/moltis-key" {
  capabilities = ["update"]
}

path "transit/decrypt/moltis-key" {
  capabilities = ["update"]
}
```

### Token Self-Management

```hcl
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

### AppRole Setup (CLI)

```bash
# Create the role
vault write auth/approle/role/moltis-gateway \
  token_policies="moltis-gateway-kv,moltis-gateway-transit,moltis-gateway-token" \
  token_ttl=1h \
  token_max_ttl=24h

# Get the role_id
vault read auth/approle/role/moltis-gateway/role-id

# Generate a wrapped secret_id (single use)
vault write -wrap-ttl=5m -f auth/approle/role/moltis-gateway/secret-id
```

## Consul Intention Setup

Service intentions control which services can connect to Moltis through the
Connect mesh:

```bash
# Allow all services (development)
consul intention create -allow '*' moltis-gateway

# Allow specific services (production)
consul intention create -allow web moltis-gateway
consul intention create -allow api moltis-gateway
```

Or via the Terraform module which creates a `service-intentions` config entry.

## mTLS Configuration

When your HashiCorp cluster enforces mutual TLS, configure client certificates
for each service:

1. **Generate or obtain** a client certificate signed by the cluster's CA.
2. **Set the paths** in `moltis.toml`:

```toml
[hc_vault]
address         = "https://vault.example.com:8200"
tls_ca_cert     = "/etc/tls/vault-ca.pem"
tls_client_cert = "/etc/tls/client.pem"
tls_client_key  = "/etc/tls/client-key.pem"
```

The `tls_client_cert` must be a PEM-encoded certificate and `tls_client_key`
must be a PEM-encoded PKCS#8 private key. The same pattern applies to the
`[consul]` and `[nomad]` sections.

If only `tls_ca_cert` is set (without client cert/key), the connection uses
one-way TLS — Moltis verifies the server's certificate but does not present
a client certificate.

## Environment Variable Interpolation

All string values in `moltis.toml` support `${ENV_VAR}` syntax. Variables are
resolved at config load time. This is useful for:

- **Terraform/Nomad templates**: inject addresses and credentials at deploy time
- **Kubernetes**: mount secrets as env vars via `envFrom`
- **CI/CD**: pass credentials without writing them to disk

```toml
[hc_vault]
address   = "${VAULT_ADDR}"
secret_id = "${VAULT_SECRET_ID}"

[consul]
address = "${CONSUL_HTTP_ADDR}"
token   = "${CONSUL_HTTP_TOKEN}"
```

Undefined variables are left as-is (no error), allowing partial configuration
where some values come from env and others are static.

## Terraform Provisioning

The `deploy/terraform/hashicorp-mesh/` module automates all of the above:

```bash
cd deploy/terraform/hashicorp-mesh

terraform init
terraform plan \
  -var vault_address=https://vault.example.com:8200 \
  -var consul_address=https://consul.example.com:8500

terraform apply
```

After apply, use the outputs:

```bash
# Get the moltis.toml snippet
terraform output moltis_toml_snippet

# Get the role_id
terraform output vault_role_id

# Unwrap the secret_id (must be done within 5 minutes)
vault unwrap $(terraform output -raw vault_wrapped_secret_id)
```
