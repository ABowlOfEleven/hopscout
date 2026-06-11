//! Capability model. Features declare what they need; the backend reports what's
//! available, and frontends decide what to offer rather than asking "are we
//! elevated?" everywhere.

/// What the current process can actually do, networking-wise.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    /// Process token is elevated (admin).
    pub elevated: bool,
    /// A raw `SIO_RCVALL` sniffer could be stood up — gate for rung-2 UDP mode.
    pub raw_icmp: bool,
    /// Npcap (`wpcap.dll`) is installed — gate for rung-3 full packet craft.
    pub npcap: bool,
}

impl Capabilities {
    /// Rung-2 UDP traceroute: needs to receive ICMP errors on a raw socket.
    pub fn rung2(&self) -> bool {
        self.raw_icmp
    }

    /// Rung-3 TCP-SYN / Paris multipath: needs Npcap (and admin to inject).
    pub fn rung3(&self) -> bool {
        self.npcap
    }
}
