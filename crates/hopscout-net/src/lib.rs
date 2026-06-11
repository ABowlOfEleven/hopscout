//! hopscout-net - the one crate allowed to touch Win32.
//!
//! * Rung 1: [`IcmpBackend`] on `Icmp[6]SendEcho2` - no elevation, IPv4 + IPv6.
//! * Rung 2: [`RawUdpBackend`] - UDP traceroute via a raw ICMP receive socket
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
mod ext;
#[cfg(windows)]
mod factory;
#[cfg(windows)]
mod icmp;
#[cfg(windows)]
mod iface;
#[cfg(windows)]
mod ipc;
#[cfg(windows)]
mod npcap;
#[cfg(windows)]
mod packet;
#[cfg(windows)]
mod raw;
#[cfg(windows)]
mod tcp;

#[cfg(windows)]
pub use caps::detect as detect_caps;
#[cfg(windows)]
pub use elevate::{relaunch_elevated, spawn_helper_elevated};
#[cfg(windows)]
pub use factory::{BackendError, make_factory};
#[cfg(windows)]
pub use ipc::{HelperBackend, HelperBackendFactory, PIPE_NAME, serve as serve_helper};
#[cfg(windows)]
pub use icmp::{IcmpBackend, IcmpBackendFactory, path_mtu};
#[cfg(windows)]
pub use npcap::Npcap;
#[cfg(windows)]
pub use raw::{IcmpReceiver, RawUdpBackend, RawUdpBackendFactory, local_ipv4_for};
#[cfg(windows)]
pub use tcp::NpcapTcpBackendFactory;

pub use hopscout_core::Capabilities;
