//! Protocol → backend selection, shared by the CLI and GUI so capability gating
//! lives in exactly one place.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use hopscout_core::{BackendFactory, ProbeProtocol};

use crate::{
    IcmpBackendFactory, NpcapTcpBackendFactory, RawUdpBackendFactory, detect_caps, local_ipv4_for,
};

/// Why a backend couldn't be built - frontends turn these into prompts.
#[derive(Debug)]
pub enum BackendError {
    /// Needs an elevated process (raw sniffer / packet injection).
    NeedsElevation,
    /// Needs Npcap installed (rung-3 TCP mode).
    NeedsNpcap,
    /// Protocol can't serve this target (e.g. UDP/TCP to an IPv6 address).
    Unsupported(String),
    /// A real I/O failure opening sockets / resolving the interface.
    Io(io::Error),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedsElevation => write!(f, "this mode needs administrator privileges"),
            Self::NeedsNpcap => write!(f, "this mode needs Npcap (install from https://npcap.com)"),
            Self::Unsupported(m) => write!(f, "{m}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Build the probe backend factory for `proto` toward `dest`.
pub fn make_factory(
    proto: ProbeProtocol,
    dest: IpAddr,
    port: u16,
) -> Result<Arc<dyn BackendFactory>, BackendError> {
    match proto {
        ProbeProtocol::Icmp => Ok(Arc::new(IcmpBackendFactory)),

        ProbeProtocol::Udp => {
            let IpAddr::V4(d4) = dest else {
                return Err(BackendError::Unsupported("UDP mode is IPv4-only".into()));
            };
            if !detect_caps().rung2() {
                return Err(BackendError::NeedsElevation);
            }
            let local = local_ipv4_for(d4).map_err(BackendError::Io)?;
            RawUdpBackendFactory::new(local)
                .map(|f| Arc::new(f) as Arc<dyn BackendFactory>)
                .map_err(BackendError::Io)
        }

        ProbeProtocol::TcpSyn => {
            let IpAddr::V4(d4) = dest else {
                return Err(BackendError::Unsupported("TCP mode is IPv4-only".into()));
            };
            let caps = detect_caps();
            if !caps.npcap {
                return Err(BackendError::NeedsNpcap);
            }
            if !caps.elevated {
                return Err(BackendError::NeedsElevation);
            }
            let local = local_ipv4_for(d4).map_err(BackendError::Io)?;
            NpcapTcpBackendFactory::new(d4, port, local)
                .map(|f| Arc::new(f) as Arc<dyn BackendFactory>)
                .map_err(BackendError::Io)
        }
    }
}
