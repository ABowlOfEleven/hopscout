//! hopscout-net — the one crate allowed to touch Win32.
//!
//! * Rung 1: [`IcmpBackend`] on `Icmp[6]SendEcho2` — no elevation, IPv4 + IPv6.
//! * Rung 2: [`RawUdpBackend`] — UDP traceroute via a raw ICMP receive socket
//!   (needs admin). [`detect_caps`] reports what's available and
//!   [`relaunch_elevated`] re-launches the app with a UAC prompt.
//!
//! Everything here is exposed through the safe [`hopscout_core::ProbeBackend`]
//! trait; all `unsafe` is confined to this crate behind that boundary.

#[cfg(windows)]
mod caps;
#[cfg(windows)]
mod elevate;
#[cfg(windows)]
mod icmp;
#[cfg(windows)]
mod raw;

#[cfg(windows)]
pub use caps::detect as detect_caps;
#[cfg(windows)]
pub use elevate::relaunch_elevated;
#[cfg(windows)]
pub use icmp::{IcmpBackend, IcmpBackendFactory};
#[cfg(windows)]
pub use raw::{IcmpReceiver, RawUdpBackend, RawUdpBackendFactory, local_ipv4_for};

pub use hopscout_core::Capabilities;
