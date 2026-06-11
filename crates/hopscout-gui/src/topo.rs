//! Topology view: hops laid out as TTL columns, one node per observed address.
//! A hop that shows more than one address is an ECMP fan-out (multipath). Edges
//! connect every node in column N to column N+1 — we don't track which address
//! fed which next hop, so all observed transitions are drawn. Nodes are colored
//! by origin ASN, so you can see where the path crosses networks.

use std::net::IpAddr;

use egui::{Align2, Color32, FontId};
use hopscout_core::Session;

const BG: Color32 = Color32::from_rgb(18, 24, 34);
const EDGE: Color32 = Color32::from_rgb(46, 56, 72);
const LABEL: Color32 = Color32::from_rgb(205, 214, 224);
const MUTED: Color32 = Color32::from_rgb(120, 130, 145);

pub fn show(ui: &mut egui::Ui, session: &Session) {
    let n = session.visible_hops();
    let size = egui::vec2(ui.available_width(), ui.available_height().max(240.0));
    let (rect, _resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, BG);

    if n == 0 {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "Discovering path…",
            FontId::proportional(14.0),
            MUTED,
        );
        return;
    }

    let inner = rect.shrink(30.0);
    let col_dx = if n > 1 {
        inner.width() / (n as f32 - 1.0)
    } else {
        0.0
    };

    // Build each TTL column's node positions.
    let mut cols: Vec<Vec<(egui::Pos2, String, Color32)>> = Vec::with_capacity(n);
    for i in 0..n {
        let hop = &session.hops[i];
        let x = inner.left() + col_dx * i as f32;
        let color = asn_color(hop.meta.asn);
        let mut nodes = Vec::new();
        if hop.addrs.is_empty() {
            nodes.push((egui::pos2(x, inner.center().y), "*".to_string(), MUTED));
        } else {
            let m = hop.addrs.len();
            for (j, addr) in hop.addrs.iter().enumerate() {
                let t = if m > 1 {
                    j as f32 / (m as f32 - 1.0)
                } else {
                    0.5
                };
                let y = inner.top() + inner.height() * (0.15 + 0.7 * t);
                nodes.push((egui::pos2(x, y), short_addr(addr), color));
            }
        }
        cols.push(nodes);
    }

    // Edges between consecutive columns.
    let edge = egui::Stroke::new(1.0, EDGE);
    for w in cols.windows(2) {
        for a in &w[0] {
            for b in &w[1] {
                painter.line_segment([a.0, b.0], edge);
            }
        }
    }

    // TTL headers + nodes + labels.
    let label_font = FontId::monospace(10.0);
    let ttl_font = FontId::proportional(10.0);
    for (i, col) in cols.iter().enumerate() {
        let x = inner.left() + col_dx * i as f32;
        painter.text(
            egui::pos2(x, rect.top() + 12.0),
            Align2::CENTER_CENTER,
            (i + 1).to_string(),
            ttl_font.clone(),
            MUTED,
        );
        let fan = col.len() > 1;
        for (pos, label, color) in col {
            painter.circle_filled(*pos, if fan { 6.0 } else { 5.0 }, *color);
            painter.text(
                *pos + egui::vec2(0.0, 10.0),
                Align2::CENTER_TOP,
                label,
                label_font.clone(),
                LABEL,
            );
        }
    }
}

/// Short node label: last two octets (v4) or final group (v6).
fn short_addr(a: &IpAddr) -> String {
    match a {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}", o[2], o[3])
        }
        IpAddr::V6(v6) => format!("{:x}", v6.segments()[7]),
    }
}

/// Stable, distinct-ish color per ASN (gray when unknown).
fn asn_color(asn: Option<u32>) -> Color32 {
    match asn {
        None => MUTED,
        Some(a) => {
            let h = a.wrapping_mul(2_654_435_761);
            Color32::from_rgb(
                90 + (h & 0x6f) as u8,
                90 + ((h >> 8) & 0x6f) as u8,
                90 + ((h >> 16) & 0x6f) as u8,
            )
        }
    }
}
