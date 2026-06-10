//! hopscout-net — the one crate allowed to touch Win32.
//!
//! Today it provides the rung-1 [`IcmpBackend`] built on `IcmpSendEcho2`, which
//! needs no elevation. Rung-2 (raw sockets, for UDP/TCP modes and Paris
//! multipath) and rung-3 (Npcap) will live here too, each exposed through the
//! safe [`hopscout_core::ProbeBackend`] trait.

#[cfg(windows)]
mod icmp;

#[cfg(windows)]
pub use icmp::{IcmpBackend, IcmpBackendFactory};
