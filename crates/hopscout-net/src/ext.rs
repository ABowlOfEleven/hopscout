//! Parsing ICMP extensions (RFC 4884 multipart + RFC 4950 MPLS label stack) out
//! of an ICMP Time Exceeded / Destination Unreachable message. Pure, testable.

use hopscout_core::MplsLabel;

/// Extract the MPLS label stack from an ICMP message (`icmp` starts at the type
/// byte). Returns empty if there's no extension or no MPLS object.
pub fn parse_mpls(icmp: &[u8]) -> Vec<MplsLabel> {
    if icmp.len() < 8 {
        return Vec::new();
    }
    // RFC 4884: byte 5 holds the length of the original datagram in 32-bit words
    // (for time-exceeded / dest-unreachable). 0 means the legacy 128-byte area.
    let length_words = icmp[5] as usize;
    let orig_len = if length_words > 0 { length_words * 4 } else { 128 };
    let ext_off = 8 + orig_len;
    let Some(ext) = icmp.get(ext_off..) else {
        return Vec::new();
    };
    // Need the 4-byte extension header with version 2.
    if ext.len() < 4 || (ext[0] >> 4) != 2 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut p = 4; // skip the extension header
    while p + 4 <= ext.len() {
        let obj_len = u16::from_be_bytes([ext[p], ext[p + 1]]) as usize;
        let class = ext[p + 2];
        let ctype = ext[p + 3];
        if obj_len < 4 || p + obj_len > ext.len() {
            break;
        }
        if class == 1 && ctype == 1 {
            // MPLS Label Stack object: 4-byte entries.
            let mut q = p + 4;
            while q + 4 <= p + obj_len {
                let w = u32::from_be_bytes([ext[q], ext[q + 1], ext[q + 2], ext[q + 3]]);
                out.push(MplsLabel {
                    label: w >> 12,
                    exp: ((w >> 9) & 0x7) as u8,
                    bos: (w >> 8) & 1 == 1,
                    ttl: (w & 0xff) as u8,
                });
                q += 4;
            }
        }
        p += obj_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mpls_label_stack() {
        // ICMP header (8) + original datagram (length=2 words = 8 bytes) + ext.
        let mut m = vec![11u8, 0, 0, 0, 0, 2, 0, 0];
        m.extend_from_slice(&[0u8; 8]); // original datagram
        m.extend_from_slice(&[0x20, 0, 0, 0]); // extension header, version 2
        m.extend_from_slice(&[0, 8, 1, 1]); // object: len 8, class 1, ctype 1
        let w: u32 = (100_000u32 << 12) | (5 << 9) | (1 << 8) | 64;
        m.extend_from_slice(&w.to_be_bytes());

        let labels = parse_mpls(&m);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 100_000);
        assert_eq!(labels[0].exp, 5);
        assert!(labels[0].bos);
        assert_eq!(labels[0].ttl, 64);
    }

    #[test]
    fn no_extension_is_empty() {
        let m = vec![11u8, 0, 0, 0, 0, 0, 0, 0, 0x45, 0, 0, 0];
        assert!(parse_mpls(&m).is_empty());
    }
}
