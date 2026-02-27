# ── Required ─────────────────────────────────────────────────────────────────

variable "vault_address" {
  type        = string
  description = "Vault server address (e.g. https://vault.example.com:8200)."
}

variable "consul_address" {
  type        = string
  description = "Consul agent address (e.g. https://consul.example.com:8500)."
}

variable "service_name" {
  type        = string
  description = "Service name for Consul registration and Vault policy scoping."
  default     = "moltis-gateway"
}

# ── Vault ────────────────────────────────────────────────────────────────────

variable "vault_namespace" {
  type        = string
  description = "Vault namespace (Enterprise). Leave empty for OSS."
  default     = ""
}

variable "vault_kv_mount" {
  type        = string
  description = "KV v2 secrets engine mount path."
  default     = "secret"
}

variable "vault_kv_prefix" {
  type        = string
  description = "Path prefix for all Moltis secrets in KV v2."
  default     = "moltis"
}

variable "vault_transit_mount" {
  type        = string
  description = "Transit secrets engine mount path. Set empty to disable envelope encryption."
  default     = "transit"
}

variable "vault_transit_key_name" {
  type        = string
  description = "Transit encryption key name."
  default     = "moltis-key"
}

variable "vault_approle_mount" {
  type        = string
  description = "AppRole auth method mount path."
  default     = "approle"
}

variable "vault_token_ttl" {
  type        = string
  description = "TTL for tokens issued via AppRole."
  default     = "1h"
}

variable "vault_token_max_ttl" {
  type        = string
  description = "Max TTL for tokens issued via AppRole."
  default     = "24h"
}

# ── Consul ───────────────────────────────────────────────────────────────────

variable "consul_datacenter" {
  type        = string
  description = "Consul datacenter name."
  default     = "dc1"
}

variable "consul_intention_sources" {
  type        = list(string)
  description = "Services allowed to connect to the Moltis service via Consul intentions."
  default     = ["*"]
}
