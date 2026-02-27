-- Secret storage table for the LocalSecretBackend.
-- Stores encrypted secret values with path-based addressing.
CREATE TABLE IF NOT EXISTS vault_secrets (
    path        TEXT PRIMARY KEY NOT NULL,
    value       TEXT NOT NULL,           -- encrypted (base64) value
    metadata    TEXT,                     -- optional human-readable label
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index for prefix-based listing (list_secrets).
CREATE INDEX IF NOT EXISTS idx_vault_secrets_path ON vault_secrets(path);
