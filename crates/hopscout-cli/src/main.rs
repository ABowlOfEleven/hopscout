//! hopscout CLI - an MTR-compatible traceroute monitor.
//!
//! Default is the live full-screen view (like `mtr`); `-r`/`--json`/`--csv` give
//! non-interactive report output, and `--mtu` does a one-shot path-MTU probe.

mod report;
mod ui;

use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hopscout_core::{BackendFactory, Baseline, Engine, EngineConfig, ProbeProtocol};
use hopscout_net::{BackendError, make_factory, path_mtu, relaunch_elevated};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

#[derive(Clone, Copy, PartialEq)]
enum Family {
    Auto,
    V4,
    V6,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Interactive,
    Report,
    Json,
    Csv,
    Mtu,
}

pub struct Args {
    target: String,
    family: Family,
    proto: ProbeProtocol,
    port: u16,
    interval: Duration,
    timeout: Duration,
    first_ttl: u8,
    max_ttl: u8,
    psize: usize,
    flows: u8,
    cycles: u32,
    mode: Mode,
    no_dns: bool,
    show_ips: bool,
    wide: bool,
}

fn main() -> io::Result<()> {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => return Ok(()),
        Err(msg) => {
            eprintln!("hopscout: {msg}\n");
            usage();
            std::process::exit(2);
        }
    };

    let Some(dest) = resolve(&args.target, args.family) else {
        eprintln!("hopscout: could not resolve an address for '{}'", args.target);
        std::process::exit(1);
    };

    if args.mode == Mode::Mtu {
        let IpAddr::V4(v4) = dest else {
            eprintln!("hopscout: --mtu is IPv4-only");
            std::process::exit(1);
        };
        match path_mtu(v4, Duration::from_millis(800)) {
            Ok(Some(m)) => println!("Path MTU to {} ({v4}): {m} bytes", args.target),
            Ok(None) => println!("{} ({v4}) did not answer ping; cannot probe MTU", args.target),
            Err(e) => {
                eprintln!("hopscout: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    let mut config = EngineConfig::new(dest);
    config.interval = args.interval;
    config.timeout = args.timeout;
    config.max_hops = args.max_ttl;
    config.first_ttl = args.first_ttl.clamp(1, args.max_ttl);
    config.payload_size = args.psize;
    config.flows = args.flows.max(1);
    config.protocol = args.proto;

    let Some(factory) = build_factory(args.proto, dest, args.port) else {
        return Ok(());
    };

    let engine = Engine::start(config.clone(), factory)?;
    let enricher = hopscout_enrich::spawn_with(engine.session(), !args.no_dns);

    let result = match args.mode {
        Mode::Interactive => run_tui(&engine, &args.target, &config),
        Mode::Report | Mode::Json | Mode::Csv => run_report(&engine, &args, &config),
        Mode::Mtu => Ok(()),
    };

    enricher.stop();
    engine.stop();
    result
}

/// The interactive full-screen view.
fn run_tui(engine: &Engine, target_label: &str, config: &EngineConfig) -> io::Result<()> {
    let mut terminal = ratatui::init();
    let out = tui_loop(&mut terminal, engine, target_label, config);
    ratatui::restore();
    out
}

fn tui_loop(
    terminal: &mut ratatui::DefaultTerminal,
    engine: &Engine,
    target_label: &str,
    config: &EngineConfig,
) -> io::Result<()> {
    let mut baseline: Option<Baseline> = None;
    loop {
        let snapshot = engine.snapshot();
        let alerts = baseline
            .as_ref()
            .map(|b| b.deviations(&snapshot, 1.5))
            .unwrap_or_default();
        terminal.draw(|frame| {
            ui::draw(frame, &snapshot, engine, target_label, config, baseline.is_some(), &alerts)
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('p') | KeyCode::Char(' ') => engine.toggle_pause(),
                    KeyCode::Char('r') => engine.reset(),
                    KeyCode::Char('b') => baseline = Some(Baseline::capture(&snapshot)),
                    _ => {}
                }
            }
        }
    }
}

/// Run until each hop has `cycles` samples (or a deadline), then print a report.
fn run_report(engine: &Engine, args: &Args, config: &EngineConfig) -> io::Result<()> {
    let per_cycle = config.interval.max(Duration::from_millis(50));
    let deadline = Instant::now() + per_cycle * (args.cycles + 4) + Duration::from_secs(3);

    loop {
        let snap = engine.snapshot();
        let ready = snap.path_len.is_some()
            && report::min_samples(&snap, config.first_ttl) >= args.cycles as u64;
        if ready || Instant::now() >= deadline {
            match args.mode {
                Mode::Json => print!("{}", report::json(&snap, args, config)),
                Mode::Csv => print!("{}", report::csv(&snap, args, config)),
                _ => print!("{}", report::text(&snap, args, config)),
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn build_factory(proto: ProbeProtocol, dest: IpAddr, port: u16) -> Option<Arc<dyn BackendFactory>> {
    match make_factory(proto, dest, port) {
        Ok(factory) => Some(factory),
        Err(BackendError::NeedsElevation) => {
            eprintln!("hopscout: this mode needs admin - relaunching elevated...");
            match relaunch_elevated() {
                Ok(()) => None,
                Err(e) => {
                    eprintln!("hopscout: elevation failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("hopscout: {e}");
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut target: Option<String> = None;
    let mut family = Family::Auto;
    let mut proto = ProbeProtocol::Icmp;
    let mut port = 443u16;
    let mut interval = Duration::from_secs(1);
    let mut timeout = Duration::from_secs(1);
    let mut first_ttl = 1u8;
    let mut max_ttl = 30u8;
    let mut psize = 32usize;
    let mut flows = 1u8;
    let mut cycles = 10u32;
    let mut no_dns = false;
    let mut show_ips = false;
    let mut wide = false;
    let mut report = false;
    let mut json = false;
    let mut csv = false;
    let mut mtu = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(None);
            }
            "-v" | "-V" | "--version" => {
                println!("{}", hopscout_core::brand::name_version());
                return Ok(None);
            }
            "-r" | "--report" => report = true,
            "-j" | "--json" => json = true,
            "-C" | "--csv" => csv = true,
            "--mtu" => mtu = true,
            "-w" | "--report-wide" => wide = true,
            "-n" | "--no-dns" => no_dns = true,
            "-b" | "--show-ips" => show_ips = true,
            "-e" | "--aslookup" => {} // ASN is always shown in hopscout
            "-4" => family = Family::V4,
            "-6" => family = Family::V6,
            "-u" | "--udp" => proto = ProbeProtocol::Udp,
            "-T" | "--tcp" => proto = ProbeProtocol::TcpSyn,
            "-c" | "--report-cycles" => cycles = next_num(&mut it, "report-cycles")?,
            "-P" | "--port" => port = next_num(&mut it, "port")?,
            "-s" | "--psize" => psize = next_num(&mut it, "psize")?,
            "-m" | "--max-ttl" => max_ttl = next_num(&mut it, "max-ttl")?,
            "-f" | "--first-ttl" => first_ttl = next_num(&mut it, "first-ttl")?,
            "-i" | "--interval" => interval = Duration::from_secs_f64(next_f64(&mut it, "interval")?),
            "--timeout" => timeout = Duration::from_secs_f64(next_f64(&mut it, "timeout")?),
            "--flows" => flows = next_num(&mut it, "flows")?,
            // Accepted for MTR compatibility but not yet implemented.
            "-z" | "--mpls" => eprintln!("hopscout: note: MPLS (-z) is not supported yet"),
            "-x" | "--xml" => eprintln!("hopscout: note: XML output is not supported yet"),
            "-a" | "--address" => {
                let _ = it.next();
                eprintln!("hopscout: note: source --address is not supported yet");
            }
            other if other.starts_with('-') => return Err(format!("unknown flag '{other}'")),
            other => {
                if target.replace(other.to_string()).is_some() {
                    return Err("more than one target given".to_string());
                }
            }
        }
    }

    let target = target.ok_or("missing target host")?;
    if max_ttl == 0 {
        return Err("max-ttl must be >= 1".to_string());
    }
    let mode = if mtu {
        Mode::Mtu
    } else if json {
        Mode::Json
    } else if csv {
        Mode::Csv
    } else if report {
        Mode::Report
    } else {
        Mode::Interactive
    };

    Ok(Some(Args {
        target,
        family,
        proto,
        port,
        interval,
        timeout,
        first_ttl,
        max_ttl,
        psize,
        flows,
        cycles,
        mode,
        no_dns,
        show_ips,
        wide,
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

fn next_f64(it: &mut impl Iterator<Item = String>, name: &str) -> Result<f64, String> {
    next_num(it, name)
}

fn usage() {
    eprintln!(
        "hopscout - live traceroute monitor (MTR-compatible)\n\
         \n\
         USAGE:\n    hopscout [options] <host>\n\
         \n\
         REPORT:\n\
         \x20   -r, --report           non-interactive report after N cycles\n\
         \x20   -c, --report-cycles N  cycles to run for a report   [default: 10]\n\
         \x20   -w, --report-wide      don't truncate host names\n\
         \x20   -j, --json             JSON report\n\
         \x20   -C, --csv              CSV report\n\
         \n\
         PROBES:\n\
         \x20   -u, --udp              UDP mode (needs admin)\n\
         \x20   -T, --tcp              TCP-SYN mode (needs Npcap + admin)\n\
         \x20   -P, --port N           destination port (tcp)       [default: 443]\n\
         \x20   -s, --psize N          payload bytes                [default: 32]\n\
         \x20   -i, --interval SEC     seconds between probes       [default: 1]\n\
         \x20       --timeout SEC      per-probe timeout            [default: 1]\n\
         \x20   -m, --max-ttl N        maximum hops                 [default: 30]\n\
         \x20   -f, --first-ttl N      first hop                    [default: 1]\n\
         \x20   -4 / -6                force IPv4 / IPv6\n\
         \x20       --flows N          concurrent flows (multipath) [default: 1]\n\
         \x20       --mtu              probe path MTU and exit\n\
         \n\
         DISPLAY:\n\
         \x20   -n, --no-dns           don't resolve host names\n\
         \x20   -b, --show-ips         show IPs alongside names\n\
         \x20   -e, --aslookup         AS lookup (always on)\n\
         \x20   -v, --version          print version\n\
         \x20   -h, --help             show this help\n\
         \n\
         KEYS (interactive):  q quit  p pause  r reset  b baseline"
    );
}

/// Resolve a host or literal to an address, honoring the family preference.
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
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs.into_iter().next()
}
