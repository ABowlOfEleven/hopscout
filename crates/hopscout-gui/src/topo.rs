//! Topology view. Hops are laid out as TTL columns, one node per observed
//! address (a column with several nodes is an ECMP fan-out). When multiple
//! flows are probed, each flow's path is drawn as its own colored polyline, so
//! divergence and reconvergence through load balancers are visible. Nodes are
//! colored by origin ASN - line color = which flow, node color = which network.

use std::collections::HashMap;
use std::net::IpAddr;

use egui::{Align2, Color32, FontId};
use hopscout_core::Session;

use crate::theme::Theme;

pub fn show(ui: &mut egui::Ui, session: &Session, theme: &Theme) {
    let bg = theme.surface;
    let label_color = theme.text;
    let muted = theme.muted;
    let n = session.visible_hops();
    let size = egui::vec2(ui.available_width(), ui.available_height().max(240.0));
    let (rect, _resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, bg);

    if n == 0 {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "Discovering path…",
            FontId::proportional(14.0),
            muted,
        );
        return;
    }

    let inner = rect.shrink(30.0);
    let col_dx = if n > 1 {
        inner.width() / (n as f32 - 1.0)
    } else {
        0.0
    };
    let y_for = |j: usize, m: usize| {
        let t = if m > 1 { j as f32 / (m as f32 - 1.0) } else { 0.5 };
        inner.top() + inner.height() * (0.15 + 0.7 * t)
    };

    // One node position per (column, address) from the union of observed addrs.
    let mut node_pos: HashMap<(usize, IpAddr), egui::Pos2> = HashMap::new();
    for i in 0..n {
        let addrs = &session.hops[i].addrs;
        let x = inner.left() + col_dx * i as f32;
        for (j, addr) in addrs.iter().enumerate() {
            node_pos.insert((i, *addr), egui::pos2(x, y_for(j, addrs.len())));
        }
    }

    // Per-flow polylines: connect consecutive responding TTLs for each flow.
    for (fi, path) in session.paths.iter().enumerate() {
        let stroke = egui::Stroke::new(1.6, theme.flow_color(fi));
        let mut prev: Option<egui::Pos2> = None;
        for (i, slot) in path.iter().take(n).enumerate() {
            match slot.and_then(|addr| node_pos.get(&(i, addr)).copied()) {
                Some(pos) => {
                    if let Some(p) = prev {
                        painter.line_segment([p, pos], stroke);
                    }
                    prev = Some(pos);
                }
                None => prev = None, // non-responding hop breaks the line
            }
        }
    }

    // TTL headers + nodes + labels.
    let label_font = FontId::monospace(10.0);
    let ttl_font = FontId::proportional(10.0);
    for i in 0..n {
        let x = inner.left() + col_dx * i as f32;
        painter.text(
            egui::pos2(x, rect.top() + 12.0),
            Align2::CENTER_CENTER,
            (i + 1).to_string(),
            ttl_font.clone(),
            muted,
        );
        let hop = &session.hops[i];
        if hop.addrs.is_empty() {
            painter.circle_filled(egui::pos2(x, y_for(0, 1)), 4.0, muted);
            continue;
        }
        let color = asn_color(hop.meta.asn, theme);
        let fan = hop.addrs.len() > 1;
        for addr in &hop.addrs {
            let pos = node_pos[&(i, *addr)];
            painter.circle_filled(pos, if fan { 6.0 } else { 5.0 }, color);
            painter.text(
                pos + egui::vec2(0.0, 10.0),
                Align2::CENTER_TOP,
                short_addr(addr),
                label_font.clone(),
                label_color,
            );
        }
    }

    if session.paths.len() > 1 {
        painter.text(
            egui::pos2(rect.right() - 8.0, rect.top() + 12.0),
            Align2::RIGHT_CENTER,
            format!("{} flows", session.paths.len()),
            ttl_font,
            muted,
        );
    }
}

fn short_addr(a: &IpAddr) -> String {
    match a {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}", o[2], o[3])
        }
        IpAddr::V6(v6) => format!("{:x}", v6.segments()[7]),
    }
}

fn asn_color(asn: Option<u32>, theme: &Theme) -> Color32 {
    match asn {
        None => theme.muted,
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
