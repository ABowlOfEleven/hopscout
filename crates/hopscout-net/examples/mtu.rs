//! Path MTU discovery probe:  cargo run -p hopscout-net --example mtu -- 8.8.8.8

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "8.8.8.8".to_string());
    let Some(IpAddr::V4(v4)) = resolve(&target) else {
        eprintln!("need an IPv4 target");
        std::process::exit(1);
    };
    match hopscout_net::path_mtu(v4, Duration::from_millis(800)) {
        Ok(Some(mtu)) => println!("Path MTU to {target} ({v4}): {mtu} bytes"),
        Ok(None) => println!("{target} ({v4}) did not answer ping; cannot probe MTU"),
        Err(e) => eprintln!("error: {e}"),
    }
}

fn resolve(t: &str) -> Option<IpAddr> {
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some(ip);
    }
    (t, 0u16).to_socket_addrs().ok()?.find(|s| s.is_ipv4()).map(|s| s.ip())
}
