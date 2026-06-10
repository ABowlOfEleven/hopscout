//! hopscout CLI — a live, MTR-style trace table over the concurrent engine.
//!
//!   hopscout 8.8.8.8
//!   hopscout one.one.one.one -i 500 -m 40
//!
//! Keys: q/Esc quit · p/space pause · r reset

mod ui;

use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use hopscout_core::{Engine, EngineConfig};
use hopscout_net::IcmpBackendFactory;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

#[derive(Clone, Copy, PartialEq)]
enum Family {
    Auto,
    V4,
    V6,
}

struct Args {
    target: String,
    interval: Duration,
    timeout: Duration,
    max_hops: u8,
    size: usize,
    family: Family,
}

fn main() -> io::Result<()> {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => return Ok(()), // --help
        Err(msg) => {
            eprintln!("hopscout: {msg}\n");
            usage();
            std::process::exit(2);
        }
    };

    let Some(dest) = resolve(&args.target, args.family) else {
        eprintln!("hopscout: could not resolve an IPv4 address for '{}'", args.target);
        std::process::exit(1);
    };

    let mut config = EngineConfig::new(dest);
    config.interval = args.interval;
    config.timeout = args.timeout;
    config.max_hops = args.max_hops;
    config.payload_size = args.size;

    let engine = Engine::start(config.clone(), Arc::new(IcmpBackendFactory))?;
    // Background rDNS + ASN enrichment fills hostnames/AS info as hops appear.
    let enricher = hopscout_enrich::spawn(engine.session());

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &engine, &args.target, &config);
    ratatui::restore();
    enricher.stop();
    engine.stop();
    result
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    engine: &Engine,
    target_label: &str,
    config: &EngineConfig,
) -> io::Result<()> {
    loop {
        let snapshot = engine.snapshot();
        terminal.draw(|frame| ui::draw(frame, &snapshot, engine, target_label, config))?;

        // ~5 fps redraw cadence; also our input poll.
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('p') | KeyCode::Char(' ') => engine.toggle_pause(),
                    KeyCode::Char('r') => engine.reset(),
                    _ => {}
                }
            }
        }
    }
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut target: Option<String> = None;
    let mut interval = 1000u64;
    let mut timeout = 1000u64;
    let mut max_hops = 30u8;
    let mut size = 32usize;

    let mut family = Family::Auto;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(None);
            }
            "-4" => family = Family::V4,
            "-6" => family = Family::V6,
            "-i" | "--interval" => interval = next_num(&mut it, "interval")?,
            "-w" | "--timeout" => timeout = next_num(&mut it, "timeout")?,
            "-m" | "--max-hops" => max_hops = next_num(&mut it, "max-hops")?,
            "-s" | "--size" => size = next_num(&mut it, "size")?,
            other if other.starts_with('-') => {
                return Err(format!("unknown flag '{other}'"));
            }
            other => {
                if target.replace(other.to_string()).is_some() {
                    return Err("more than one target given".to_string());
                }
            }
        }
    }

    let target = target.ok_or("missing target host")?;
    if max_hops == 0 {
        return Err("max-hops must be >= 1".to_string());
    }
    Ok(Some(Args {
        target,
        interval: Duration::from_millis(interval),
        timeout: Duration::from_millis(timeout),
        max_hops,
        size,
        family,
    }))
}

fn next_num<T: std::str::FromStr>(
    it: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<T, String> {
    let raw = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
    raw.parse::<T>()
        .map_err(|_| format!("--{name} value '{raw}' is not a number"))
}

fn usage() {
    eprintln!(
        "hopscout — live traceroute monitor (rung-1 ICMP, unprivileged)\n\
         \n\
         USAGE:\n    hopscout <host> [options]\n\
         \n\
         OPTIONS:\n\
         \x20   -i, --interval <ms>   delay between probes per hop  [default: 1000]\n\
         \x20   -w, --timeout  <ms>   per-probe timeout             [default: 1000]\n\
         \x20   -m, --max-hops <n>    maximum TTL to probe          [default: 30]\n\
         \x20   -s, --size     <n>    payload bytes                 [default: 32]\n\
         \x20   -4 / -6               force IPv4 / IPv6             [default: auto]\n\
         \x20   -h, --help            show this help\n\
         \n\
         KEYS:\n    q/Esc quit   p/space pause   r reset"
    );
}

/// Resolve a host or literal to an address, honoring the family preference
/// (`Auto` prefers IPv4 then falls back to IPv6).
fn resolve(target: &str, family: Family) -> Option<IpAddr> {
    let matches = |a: &IpAddr| match family {
        Family::Auto => true,
        Family::V4 => a.is_ipv4(),
        Family::V6 => a.is_ipv6(),
    };
    if let Ok(ip) = target.parse::<IpAddr>() {
        return matches(&ip).then_some(ip);
    }
    let mut addrs: Vec<IpAddr> = (target, 0u16)
        .to_socket_addrs()
        .ok()?
        .map(|s| s.ip())
        .filter(matches)
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6()); // Auto prefers IPv4
    addrs.into_iter().next()
}
