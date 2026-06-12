//! Non-interactive report output: MTR-style text, JSON, and CSV.
//!
//! Shared by the CLI (`-r`/`-j`/`-C`) and the GUI's Export button. The caller
//! fills in a [`ReportParams`] describing how to render; the generators below
//! turn a [`Session`] snapshot into a string.

use crate::fields::Field;
use crate::Session;

/// How to render a report. Built from CLI args or GUI state.
pub struct ReportParams {
    /// Target label shown in the header (host name or IP as the user typed it).
    pub target: String,
    /// First TTL to include (1-based); rows before it are skipped.
    pub first_ttl: u8,
    /// Payload size, echoed into the JSON `psize` field.
    pub psize: usize,
    /// Cycle count, echoed into the JSON `tests` field.
    pub cycles: u32,
    /// Don't truncate host names in the text report.
    pub wide: bool,
    /// Treat host names as absent (mirrors `--no-dns`).
    pub no_dns: bool,
    /// Show `name (ip)` instead of just the name.
    pub show_ips: bool,
    /// Include MPLS label lines in the text report.
    pub mpls: bool,
    /// Stat columns, in order.
    pub fields: Vec<Field>,
}

impl ReportParams {
    /// A reasonable default set of columns and flags for a target label.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            first_ttl: 1,
            psize: 32,
            cycles: 0,
            wide: false,
            no_dns: false,
            show_ips: false,
            mpls: false,
            fields: crate::fields::default(),
        }
    }
}

/// Smallest sample count across the visible hops (drives "are we done yet?").
pub fn min_samples(s: &Session, first_ttl: u8) -> u64 {
    let start = (first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();
    if start >= n {
        return 0;
    }
    (start..n).map(|i| s.hops[i].stat.sent()).min().unwrap_or(0)
}

fn host_label(s: &Session, i: usize, p: &ReportParams) -> String {
    let hop = &s.hops[i];
    let ip = hop.primary_addr().map(|a| a.to_string());
    let name = if p.no_dns { None } else { hop.meta.hostname.clone() };
    match (name, ip) {
        (Some(n), Some(ip)) if p.show_ips => format!("{n} ({ip})"),
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
pub fn text(s: &Session, p: &ReportParams) -> String {
    let start = (p.first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();

    let mut out = String::new();
    let mut header = format!("{:<8}{:<33}", "HOST:", p.target);
    for f in &p.fields {
        header.push_str(&format!(" {:>w$}", f.header(), w = f.width() as usize));
    }
    header.push('\n');
    out.push_str(&header);

    for i in start..n {
        let st = &s.hops[i].stat;
        let host = host_label(s, i, p);
        let host = if p.wide { host } else { truncate(&host, 33) };
        let mut row = format!("{:>3}.|-- {:<33}", i + 1, host);
        for f in &p.fields {
            row.push_str(&format!(" {:>w$}", f.value(st), w = f.width() as usize));
        }
        row.push('\n');
        out.push_str(&row);
        if p.mpls {
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

/// MTR-compatible JSON report. City/country are appended per hub (extra fields
/// MTR parsers ignore) when geolocation is known.
pub fn json(s: &Session, p: &ReportParams) -> String {
    let start = (p.first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();
    let g = |v: Option<f64>| v.unwrap_or(0.0);

    let mut hubs = String::new();
    for i in start..n {
        let hop = &s.hops[i];
        let st = &hop.stat;
        let host = host_label(s, i, p);
        if i > start {
            hubs.push(',');
        }
        hubs.push_str(&format!(
            "{{\"count\":{},\"host\":\"{}\",\"Loss%\":{:.2},\"Snt\":{},\"Last\":{:.2},\"Avg\":{:.2},\"Best\":{:.2},\"Wrst\":{:.2},\"StDev\":{:.2}",
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
        if let Some(asn) = hop.meta.asn {
            hubs.push_str(&format!(",\"ASN\":{asn}"));
        }
        if let Some(city) = &hop.meta.city {
            if !city.is_empty() {
                hubs.push_str(&format!(",\"city\":\"{}\"", json_escape(city)));
            }
        }
        if let Some(country) = &hop.meta.country {
            if !country.is_empty() {
                hubs.push_str(&format!(",\"country\":\"{}\"", json_escape(country)));
            }
        }
        hubs.push('}');
    }
    format!(
        "{{\"report\":{{\"mtr\":{{\"src\":\"\",\"dst\":\"{}\",\"psize\":\"{}\",\"tests\":\"{}\"}},\"hubs\":[{}]}}}}\n",
        json_escape(&p.target),
        p.psize,
        p.cycles,
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

/// CSV report (one row per hop), including geolocation columns.
pub fn csv(s: &Session, p: &ReportParams) -> String {
    let start = (p.first_ttl as usize).saturating_sub(1);
    let n = s.visible_hops();
    let g = |v: Option<f64>| v.map(|x| format!("{x:.1}")).unwrap_or_default();

    let mut out = String::from("Hop,Ip,Host,ASN,City,Country,Loss%,Snt,Last,Avg,Best,Wrst,StDev\n");
    for i in start..n {
        let hop = &s.hops[i];
        let st = &hop.stat;
        let ip = hop.primary_addr().map(|a| a.to_string()).unwrap_or_default();
        let host = if p.no_dns {
            String::new()
        } else {
            hop.meta.hostname.clone().unwrap_or_default()
        };
        let asn = hop.meta.asn.map(|a| format!("AS{a}")).unwrap_or_default();
        let city = hop.meta.city.clone().unwrap_or_default();
        let country = hop.meta.country.clone().unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{},{},{:.1},{},{},{},{},{},{}\n",
            i + 1,
            csv_field(&ip),
            csv_field(&host),
            asn,
            csv_field(&city),
            csv_field(&country),
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
