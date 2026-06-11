//! Headless smoke test for the concurrent engine + rung-1 ICMP backend.
//! Starts the engine, lets it run a few seconds, prints a snapshot, stops.
//!
//!   cargo run -p hopscout-net --example trace -- 8.8.8.8
//!   cargo run -p hopscout-net --example trace -- one.one.one.one 4

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use hopscout_core::{BackendFactory, Engine, EngineConfig, ProbeProtocol};
use hopscout_net::{IcmpBackendFactory, RawUdpBackendFactory};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "8.8.8.8".to_string());
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(4);
    let proto = args.next().unwrap_or_default();

    let Some(dest) = resolve(&target) else {
        eprintln!("could not resolve an IPv4 address for '{target}'");
        std::process::exit(1);
    };

    println!("hopscout engine smoke -> {target} ({dest}), sampling {secs}s\n");

    let mut config = EngineConfig::new(dest);
    config.interval = Duration::from_millis(500);

    let factory: Arc<dyn BackendFactory> = if proto.eq_ignore_ascii_case("udp") {
        config.protocol = ProbeProtocol::Udp;
        let IpAddr::V4(d4) = dest else {
            eprintln!("UDP mode is IPv4-only");
            std::process::exit(1);
        };
        let local = hopscout_net::local_ipv4_for(d4)?;
        println!("(rung-2 UDP mode, bind {local})\n");
        Arc::new(RawUdpBackendFactory::new(local)?)
    } else if proto.eq_ignore_ascii_case("tcp") {
        config.protocol = ProbeProtocol::TcpSyn;
        let IpAddr::V4(d4) = dest else {
            eprintln!("TCP mode is IPv4-only");
            std::process::exit(1);
        };
        let local = hopscout_net::local_ipv4_for(d4)?;
        println!("(rung-3 TCP-SYN mode :443, bind {local})\n");
        Arc::new(hopscout_net::NpcapTcpBackendFactory::new(d4, 443, local)?)
    } else {
        Arc::new(IcmpBackendFactory)
    };
    let engine = Engine::start(config, factory)?;
    let enricher = hopscout_enrich::spawn(engine.session());

    sleep(Duration::from_secs(secs));
    let s = engine.snapshot();

    println!(
        "{:>3}  {:<28}  {:>8}  {:>6}  {:>8}  {:>8}",
        "TTL", "Host", "ASN", "Loss%", "Last", "Avg"
    );
    for i in 0..s.visible_hops() {
        let hop = &s.hops[i];
        let host = hop
            .meta
            .hostname
            .clone()
            .or_else(|| hop.primary_addr().map(|a| a.to_string()))
            .unwrap_or_else(|| "*".to_string());
        let asn = hop.meta.asn.map(|n| format!("AS{n}")).unwrap_or_default();
        let f = |v: Option<f64>| v.map(|x| format!("{x:.1}ms")).unwrap_or_else(|| "-".into());
        println!(
            "{:>3}  {host:<28.28}  {asn:>8}  {:>5.0}%  {:>8}  {:>8}",
            i + 1,
            hop.stat.loss_pct(),
            f(hop.stat.last_ms()),
            f(hop.stat.avg_ms()),
        );
    }
    enricher.stop();
    println!(
        "\npath_len = {:?} (destination hop)",
        s.path_len
    );

    engine.stop();
    Ok(())
}

fn resolve(target: &str) -> Option<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }
    let mut addrs: Vec<IpAddr> = (target, 0u16).to_socket_addrs().ok()?.map(|s| s.ip()).collect();
    addrs.sort_by_key(|a| a.is_ipv6()); // prefer IPv4, fall back to IPv6
    addrs.into_iter().next()
}
