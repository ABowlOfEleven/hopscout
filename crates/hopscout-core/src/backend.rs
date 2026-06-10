//! The transport abstraction every probe backend implements, plus the factory
//! the engine uses to give each worker thread its own backend instance.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crate::model::{ProbeRequest, ProbeResponse};

/// A transport capable of sending one probe and reporting how it came back.
///
/// Rung-1 (`IcmpSendEcho2`) implements this with no elevation. Rung-2 (raw
/// sockets) and rung-3 (Npcap) implement the *same* trait behind the elevated
/// probe helper, so the engine and frontends never learn which rung is active —
/// they only consult the capability set to decide which features to offer.
///
/// The MVP API is synchronous (one probe, block until reply or timeout); the
/// concurrent engine layers parallelism on top by running one backend per hop.
pub trait ProbeBackend {
    /// Send one probe toward `dest` and block until it responds or `timeout`
    /// elapses. A timeout is a normal [`ProbeResponse`], not an `Err`; `Err` is
    /// reserved for backend faults (handle creation, unsupported address family).
    fn probe(
        &self,
        req: ProbeRequest,
        dest: IpAddr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse>;
}

/// Produces backend instances, one per worker thread.
///
/// Probe handles (e.g. an `IcmpCreateFile` handle) are not assumed thread-safe,
/// so the engine never shares one across threads — it asks the factory for a
/// fresh backend per hop. The factory itself is shared (`Send + Sync`).
pub trait BackendFactory: Send + Sync {
    fn create(&self) -> io::Result<Box<dyn ProbeBackend + Send>>;
}
