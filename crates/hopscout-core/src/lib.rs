//! hopscout-core - the backend-agnostic heart of hopscout.
//!
//! This crate knows nothing about Win32, sockets, or rendering. It defines the
//! probe model, the [`ProbeBackend`] trait that every transport implements, the
//! rolling [`HopStat`] statistics, and the [`Session`] that both the CLI and GUI
//! render. All of it is `#![forbid(unsafe_code)]` - the only unsafe in the
//! project lives behind the FFI boundary in `hopscout-net`.

pub mod alert;
pub mod backend;
pub mod brand;
pub mod caps;
pub mod engine;
pub mod model;
pub mod session;
pub mod stats;

pub use alert::{Alert, Baseline};
pub use backend::{BackendFactory, ProbeBackend};
pub use caps::Capabilities;
pub use engine::{Engine, EngineConfig};
pub use model::{MplsLabel, ProbeOutcome, ProbeProtocol, ProbeRequest, ProbeResponse};
pub use session::{Hop, HopMeta, Session};
pub use stats::HopStat;
