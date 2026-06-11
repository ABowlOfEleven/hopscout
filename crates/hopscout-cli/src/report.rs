//! Non-interactive report output: MTR-style text, JSON, and CSV.

use hopscout_core::{EngineConfig, Session};

use crate::Args;

/// Smallest sample count across the visible hops (drives "are we done yet?").
pub fn min_samples(s: &Session, first_ttl: u8) -> u64 {
    let start = (first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();
    if start >= n {
        return 0;
    }
    (start..n).map(|i| s.hops[i].stat.sent()).min().unwrap_or(0)
}

fn host_label(s: &Session, i: usize, args: &Args) -> String {
    let hop = &s.hops[i];
    let ip = hop.primary_addr().map(|a| a.to_string());
    let name = if args.no_dns { None } else { hop.meta.hostname.clone() };
    match (name, ip) {
        (Some(n), Some(ip)) if args.show_ips => format!("{n} ({ip})"),
        (Some(n), _) => n,
        (None, Some(ip)) => ip,
        (None, None) => "???".to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

/// MTR-style text report.
pub fn text(s: &Session, args: &Args, config: &EngineConfig) -> String {
    let start = (config.first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();

    let mut out = String::new();
    let mut header = format!("{:<8}{:<33}", "HOST:", args.target);
    for f in &args.fields {
        header.push_str(&format!(" {:>w$}", f.header(), w = f.width() as usize));
    }
    header.push('\n');
    out.push_str(&header);

    for i in start..n {
        let st = &s.hops[i].stat;
        let host = host_label(s, i, args);
        let host = if args.wide { host } else { truncate(&host, 33) };
        let mut row = format!("{:>3}.|-- {:<33}", i + 1, host);
        for f in &args.fields {
            row.push_str(&format!(" {:>w$}", f.value(st), w = f.width() as usize));
        }
        row.push('\n');
        out.push_str(&row);
        if args.mpls {
            for m in &s.hops[i].mpls {
                out.push_str(&format!(
                    "         [MPLS: Lbl {} TC {} S {} TTL {}]\n",
                    m.label, m.exp, m.bos as u8, m.ttl
                ));
            }
        }
    }
    out
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// MTR-compatible JSON report.
pub fn json(s: &Session, args: &Args, config: &EngineConfig) -> String {
    let start = (config.first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();
    let g = |v: Option<f64>| v.unwrap_or(0.0);

    let mut hubs = String::new();
    for i in start..n {
        let st = &s.hops[i].stat;
        let host = host_label(s, i, args);
        if i > start {
            hubs.push(',');
        }
        hubs.push_str(&format!(
            "{{\"count\":{},\"host\":\"{}\",\"Loss%\":{:.2},\"Snt\":{},\"Last\":{:.2},\"Avg\":{:.2},\"Best\":{:.2},\"Wrst\":{:.2},\"StDev\":{:.2}}}",
            i + 1,
            json_escape(&host),
            st.loss_pct(),
            st.sent(),
            g(st.last_ms()),
            g(st.avg_ms()),
            g(st.best_ms()),
            g(st.worst_ms()),
            g(st.stddev_ms()),
        ));
    }
    format!(
        "{{\"report\":{{\"mtr\":{{\"src\":\"\",\"dst\":\"{}\",\"psize\":\"{}\",\"tests\":\"{}\"}},\"hubs\":[{}]}}}}\n",
        json_escape(&args.target),
        args.psize,
        args.cycles,
        hubs
    )
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// CSV report (one row per hop).
pub fn csv(s: &Session, args: &Args, config: &EngineConfig) -> String {
    let start = (config.first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();
    let g = |v: Option<f64>| v.map(|x| format!("{x:.1}")).unwrap_or_default();

    let mut out = String::from("Hop,Ip,Host,ASN,Loss%,Snt,Last,Avg,Best,Wrst,StDev\n");
    for i in start..n {
        let hop = &s.hops[i];
        let st = &hop.stat;
        let ip = hop.primary_addr().map(|a| a.to_string()).unwrap_or_default();
        let host = if args.no_dns {
            String::new()
        } else {
            hop.meta.hostname.clone().unwrap_or_default()
        };
        let asn = hop.meta.asn.map(|a| format!("AS{a}")).unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{:.1},{},{},{},{},{},{}\n",
            i + 1,
            csv_field(&ip),
            csv_field(&host),
            asn,
            st.loss_pct(),
            st.sent(),
            g(st.last_ms()),
            g(st.avg_ms()),
            g(st.best_ms()),
            g(st.worst_ms()),
            g(st.stddev_ms()),
        ));
    }
    out
}
