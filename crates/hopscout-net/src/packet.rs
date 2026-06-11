//! Minimal IPv4 + TCP-SYN packet crafting for the rung-3 Npcap backend.
//!
//! Pure functions, no I/O — this is the part of rung 3 that can be fully
//! unit-tested without Npcap or admin. Npcap sends at layer 2, so we also frame
//! with Ethernet (see [`ethernet_frame`]).

use std::net::Ipv4Addr;

/// One's-complement Internet checksum (RFC 1071) over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A TCP SYN probe to a host, used for rung-3 TCP traceroute. Holding the
/// 4-tuple (src/dst port) constant across TTLs is the Paris-traceroute trick for
/// stable paths through ECMP load balancers.
pub struct TcpSyn {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ttl: u8,
    pub ip_id: u16,
}

impl TcpSyn {
    /// Build the IPv4 header + TCP SYN segment (40 bytes, no Ethernet framing).
    pub fn build(&self) -> [u8; 40] {
        let mut pkt = [0u8; 40];

        // ---- IPv4 header (20 bytes) ----
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        pkt[4..6].copy_from_slice(&self.ip_id.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
        pkt[8] = self.ttl;
        pkt[9] = 6; // protocol = TCP
        pkt[12..16].copy_from_slice(&self.src_ip.octets());
        pkt[16..20].copy_from_slice(&self.dst_ip.octets());
        let ip_ck = checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());

        // ---- TCP header (20 bytes) ----
        pkt[20..22].copy_from_slice(&self.src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&self.dst_port.to_be_bytes());
        pkt[24..28].copy_from_slice(&self.seq.to_be_bytes());
        pkt[32] = 0x50; // data offset = 5 words
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&0xffffu16.to_be_bytes()); // window

        // TCP checksum over pseudo-header + TCP segment.
        let mut pseudo = [0u8; 12 + 20];
        pseudo[0..4].copy_from_slice(&self.src_ip.octets());
        pseudo[4..8].copy_from_slice(&self.dst_ip.octets());
        pseudo[9] = 6; // protocol
        pseudo[10..12].copy_from_slice(&20u16.to_be_bytes()); // TCP length
        pseudo[12..32].copy_from_slice(&pkt[20..40]);
        let tcp_ck = checksum(&pseudo);
        pkt[36..38].copy_from_slice(&tcp_ck.to_be_bytes());

        pkt
    }
}

/// Prepend an Ethernet II header (dst MAC, src MAC, IPv4 ethertype) to `payload`.
pub fn ethernet_frame(dst_mac: [u8; 6], src_mac: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zeroes_when_field_included() {
        // A correct IPv4 header re-checksums to 0 (checksum field already set).
        let syn = TcpSyn {
            src_ip: Ipv4Addr::new(192, 168, 0, 200),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 50000,
            dst_port: 443,
            seq: 0x1234_5678,
            ttl: 7,
            ip_id: 0xABCD,
        };
        let pkt = syn.build();
        assert_eq!(checksum(&pkt[0..20]), 0, "IP header checksum should verify");
        assert_eq!(pkt[8], 7, "TTL");
        assert_eq!(pkt[9], 6, "protocol TCP");
        assert_eq!(pkt[33] & 0x02, 0x02, "SYN flag set");
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 443, "dst port");
    }

    #[test]
    fn known_checksum() {
        // Two 16-bit words 0x0001 + 0xF203 = 0xF204; complement = 0x0DFB.
        assert_eq!(checksum(&[0x00, 0x01, 0xF2, 0x03]), 0x0DFB);
    }

    #[test]
    fn ethernet_frames_prefix() {
        let f = ethernet_frame([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], &[0xAA, 0xBB]);
        assert_eq!(&f[0..6], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&f[6..12], &[7, 8, 9, 10, 11, 12]);
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        assert_eq!(&f[14..], &[0xAA, 0xBB]);
    }
}
