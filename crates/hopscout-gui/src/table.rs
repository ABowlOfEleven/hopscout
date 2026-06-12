//! The live hop table, rendered with `egui_extras::TableBuilder`. Clicking a
//! row's hop number selects it for the sparkline panel below.

use egui_extras::{Column, TableBuilder};
use hopscout_core::{Hop, Session};

use crate::theme::Theme;

const HEADERS: [&str; 12] = [
    "Hop", "Host", "ASN", "Loc", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "Jitter", "p95",
];

pub fn show(
    ui: &mut egui::Ui,
    session: &Session,
    selected: &mut Option<usize>,
    theme: &Theme,
    show_ips: bool,
    no_dns: bool,
) {
    let n = session.visible_hops();

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto()) // hop
        .column(Column::initial(220.0).at_least(120.0).clip(true)) // host
        .column(Column::auto()) // asn
        .column(Column::initial(120.0).at_least(60.0).clip(true)) // loc
        .column(Column::auto()) // loss
        .column(Column::auto()) // sent
        .column(Column::auto()) // last
        .column(Column::auto()) // avg
        .column(Column::auto()) // best
        .column(Column::auto()) // worst
        .column(Column::auto()) // jitter
        .column(Column::remainder()) // p95
        .header(20.0, |mut header| {
            for title in HEADERS {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, n, |mut row| {
                let i = row.index();
                let ttl = i + 1;
                let hop = &session.hops[i];
                let is_sel = *selected == Some(i);

                row.col(|ui| {
                    if ui.selectable_label(is_sel, ttl.to_string()).clicked() {
                        *selected = Some(i);
                    }
                });
                row.col(|ui| {
                    ui.label(host_label(hop, show_ips, no_dns));
                });
                row.col(|ui| {
                    if let Some(asn) = hop.meta.asn {
                        ui.colored_label(theme.accent2, format!("AS{asn}"));
                    }
                });
                row.col(|ui| {
                    let loc = geo_label(hop);
                    if !loc.is_empty() {
                        ui.weak(loc);
                    }
                });

                let st = &hop.stat;
                let loss = st.loss_pct();
                row.col(|ui| {
                    ui.colored_label(theme.loss(loss), format!("{loss:.0}%"));
                });
                row.col(|ui| {
                    ui.label(st.sent().to_string());
                });
                row.col(|ui| {
                    ui.label(fmt_ms(st.last_ms()));
                });
                row.col(|ui| {
                    ui.label(fmt_ms(st.avg_ms()));
                });
                row.col(|ui| {
                    ui.label(fmt_ms(st.best_ms()));
                });
                row.col(|ui| {
                    ui.label(fmt_ms(st.worst_ms()));
                });
                row.col(|ui| {
                    ui.label(fmt_ms(st.stddev_ms()));
                });
                row.col(|ui| {
                    ui.label(fmt_ms(st.p95_ms()));
                });
            });
        });
}

/// The host cell: name, `name (ip)`, or bare IP, with an MPLS suffix when the
/// hop carries labels (udp/tcp modes).
fn host_label(hop: &Hop, show_ips: bool, no_dns: bool) -> String {
    let ip = hop.primary_addr().map(|a| a.to_string());
    let name = if no_dns { None } else { hop.meta.hostname.clone() };
    let mut host = match (name, ip) {
        (Some(n), Some(ip)) if show_ips => format!("{n} ({ip})"),
        (Some(n), _) => n,
        (None, Some(ip)) => ip,
        (None, None) => "*".to_string(),
    };
    if !hop.mpls.is_empty() {
        let labels: Vec<String> = hop.mpls.iter().map(|m| m.label.to_string()).collect();
        host = format!("{host} [MPLS {}]", labels.join(","));
    }
    host
}

/// Compact location: city, else country, else blank.
fn geo_label(hop: &Hop) -> String {
    match (&hop.meta.city, &hop.meta.country) {
        (Some(c), _) if !c.is_empty() => c.clone(),
        (_, Some(c)) if !c.is_empty() => c.clone(),
        _ => String::new(),
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".to_string())
}
