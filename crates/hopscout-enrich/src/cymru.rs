//! Origin ASN lookups via Team Cymru's WHOIS netcat interface.
//!
//! Protocol (whois.cymru.com:43): send a bulk block and read the table back.
//!
//! ```text
//! begin
//! verbose
//! 8.8.8.8
//! end
//! ```
//!
//! Reply rows are pipe-delimited:
//! `AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`
//!
//! Private/unrouted addresses come back with `NA` for the AS number and are
//! simply skipped. All addresses for a round go in one connection.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

const CYMRU_HOST: &str = "whois.cymru.com";
const CYMRU_PORT: u16 = 43;
const IO_TIMEOUT: Duration = Duration::from_secs(6);

/// Resolved origin for one address.
#[derive(Debug, Clone)]
pub struct Origin {
    pub asn: u32,
    pub name: String,
}

/// Look up origin ASNs for a batch of addresses. Returns only the addresses
/// that resolved to a routable AS; failures (network, parse, private) are
/// silently omitted so the caller just sees "no ASN yet".
pub fn lookup(addrs: &[IpAddr]) -> HashMap<IpAddr, Origin> {
    query(addrs).unwrap_or_default()
}

fn query(addrs: &[IpAddr]) -> std::io::Result<HashMap<IpAddr, Origin>> {
    if addrs.is_empty() {
        return Ok(HashMap::new());
    }

    let mut stream = TcpStream::connect((CYMRU_HOST, CYMRU_PORT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    // Cymru's bulk format accepts IPv4 and IPv6 addresses interchangeably.
    let mut block = String::from("begin\nverbose\n");
    for a in addrs {
        block.push_str(&a.to_string());
        block.push('\n');
    }
    block.push_str("end\n");
    stream.write_all(block.as_bytes())?;

    // Cymru closes the connection after the "end" sentinel, so read to EOF.
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;

    Ok(parse(&resp))
}

fn parse(resp: &str) -> HashMap<IpAddr, Origin> {
    let mut out = HashMap::new();
    for line in resp.lines() {
        // Skip the banner and the header row ("AS | IP | ...").
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("Bulk mode") || trimmed.starts_with("AS ") {
            continue;
        }
        // AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() < 7 {
            continue;
        }
        let Ok(asn) = cols[0].parse::<u32>() else {
            continue; // "NA" for private/unrouted
        };
        let Ok(ip) = cols[1].parse::<IpAddr>() else {
            continue;
        };
        out.insert(
            ip,
            Origin {
                asn,
                name: cols[6].to_string(),
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verbose_table() {
        let resp = "Bulk mode; whois.cymru.com [2024-01-01 00:00:00 +0000]\n\
            AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n\
            15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE, US\n\
            NA      | 192.168.0.1      | NA                  | NA | other    |            | NA, NA\n";
        let map = parse(resp);
        assert_eq!(map.len(), 1);
        let o = &map[&"8.8.8.8".parse::<IpAddr>().unwrap()];
        assert_eq!(o.asn, 15169);
        assert_eq!(o.name, "GOOGLE, US");
    }
}
