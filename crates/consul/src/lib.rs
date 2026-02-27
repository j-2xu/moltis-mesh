//! Consul Connect integration for Moltis.
//!
//! Provides service registration, mTLS via SPIFFE x509-SVIDs from Consul's
//! Connect CA, and intention-based authorization.
//!
//! # Feature flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `tracing` | Enables `tracing::instrument` on API methods |
//! | `metrics` | Enables metric recording |

pub mod client;
pub mod config;
pub mod connect;
pub mod error;
pub mod intention;
pub mod registration;

pub use client::ConsulClient;
pub use config::ConsulConfig;
pub use connect::ConsulConnectCertManager;
pub use error::ConsulError;
pub use intention::{IntentionAuthorizer, PeerSpiffeId, intention_middleware};
pub use registration::ConsulServiceRegistry;
