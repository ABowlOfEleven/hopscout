//! Geolocation via ip-api.com's batch endpoint (free, no key, HTTP).
//!
//! Like the Cymru WHOIS lookup, this is a single batched online call per round
//! over a plain `TcpStream` - we speak HTTP/1.0 so the response is a simple
//! headers + body with no chunked transfer-encoding to unwrap.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use serde::Deserialize;

const HOST: &str = "ip-api.com";
const PORT: u16 = 80;
const IO_TIMEOUT: Duration = Duration::from_secs(6);

/// Resolved geolocation for one address.
#[derive(Debug, Clone)]
pub struct Geo {
    pub lat: f32,
    pub lon: f32,
    pub city: String,
    pub country: String,
}

#[derive(Deserialize)]
struct Entry {
    status: String,
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    #[serde(default)]
    city: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    query: String,
}

/// Look up geolocation for a batch of addresses (failures omitted).
pub fn lookup(addrs: &[IpAddr]) -> HashMap<IpAddr, Geo> {
    query(addrs).unwrap_or_default()
}

fn query(addrs: &[IpAddr]) -> std::io::Result<HashMap<IpAddr, Geo>> {
    if addrs.is_empty() {
        return Ok(HashMap::new());
    }
    let list = addrs
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!("[{list}]");
    let request = format!(
        "POST /batch?fields=status,lat,lon,city,country,query HTTP/1.0\r\n\
         Host: {HOST}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );

    let mut stream = TcpStream::connect((HOST, PORT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(request.as_bytes())?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    let text = String::from_utf8_lossy(&resp);
    let Some(idx) = text.find("\r\n\r\n") else {
        return Ok(HashMap::new());
    };
    let json = text[idx + 4..].trim();

    let entries: Vec<Entry> = serde_json::from_str(json).unwrap_or_default();
    let mut out = HashMap::new();
    for e in entries {
        if e.status != "success" {
            continue;
        }
        if let Ok(ip) = e.query.parse::<IpAddr>() {
            out.insert(
                ip,
                Geo {
                    lat: e.lat as f32,
                    lon: e.lon as f32,
                    city: e.city,
                    country: e.country,
                },
            );
        }
    }
    Ok(out)
}
