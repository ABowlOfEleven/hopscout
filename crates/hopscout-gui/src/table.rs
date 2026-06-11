//! The live hop table, rendered with `egui_extras::TableBuilder`. Clicking a
//! row's hop number selects it for the sparkline panel below.

use egui_extras::{Column, TableBuilder};
use hopscout_core::Session;

const HEADERS: [&str; 11] = [
    "Hop", "Host", "ASN", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "Jitter", "p95",
];

pub fn show(ui: &mut egui::Ui, session: &Session, selected: &mut Option<usize>) {
    let n = session.visible_hops();

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto()) // hop
        .column(Column::initial(220.0).at_least(120.0).clip(true)) // host
        .column(Column::auto()) // asn
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
                    let host = hop
                        .meta
                        .hostname
                        .clone()
                        .or_else(|| hop.primary_addr().map(|a| a.to_string()))
                        .unwrap_or_else(|| "*".to_string());
                    ui.label(host);
                });
                row.col(|ui| {
                    if let Some(asn) = hop.meta.asn {
                        ui.colored_label(egui::Color32::from_rgb(90, 170, 210), format!("AS{asn}"));
                    }
                });

                let st = &hop.stat;
                let loss = st.loss_pct();
                row.col(|ui| {
                    ui.colored_label(loss_color(loss), format!("{loss:.0}%"));
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

fn loss_color(loss: f64) -> egui::Color32 {
    if loss <= 0.0 {
        egui::Color32::from_rgb(120, 200, 120)
    } else if loss < 5.0 {
        egui::Color32::from_rgb(220, 200, 90)
    } else {
        egui::Color32::from_rgb(220, 90, 90)
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".to_string())
}
