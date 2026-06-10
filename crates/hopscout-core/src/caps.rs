//! Capability model. Features declare what they need; the backend reports what's
//! available, and frontends decide what to offer rather than asking "are we
//! elevated?" everywhere.

/// What the current process can actually do, networking-wise.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    /// Process token is elevated (admin).
    pub elevated: bool,
    /// A raw ICMP socket could be opened — the gate for rung-2 UDP/TCP modes.
    pub raw_icmp: bool,
}

impl Capabilities {
    /// Can we run rung-2 protocols (UDP/TCP traceroute) that need to receive
    /// ICMP errors on a raw socket?
    pub fn rung2(&self) -> bool {
        self.raw_icmp
    }
}
