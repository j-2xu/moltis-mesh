//! HashiCorp Vault client library.
//!
//! Provides a [`SecretBackend`](moltis_mesh::SecretBackend) implementation
//! backed by Vault's KV v2 engine, with optional Transit envelope encryption
//! and automatic token lifecycle management.
//!
//! # Feature flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `tracing` | Enables `tracing::instrument` on HTTP methods |
//! | `metrics` | Enables metric recording |

pub mod backend;
pub mod client;
pub mod config;
pub mod error;
pub mod token;

pub use backend::HcVaultBackend;
pub use client::VaultClient;
pub use config::HcVaultConfig;
pub use error::HcVaultError;
pub use token::TokenManager;
