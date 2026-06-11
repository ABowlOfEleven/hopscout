//! A dependency-free RTT sparkline, painted directly with the egui `Painter`.
//! Shows the selected hop's recent latency history (or the last hop by default).

use std::collections::VecDeque;

use hopscout_core::Session;

/// Render the sparkline panel for the selected hop.
pub fn panel(ui: &mut egui::Ui, session: &Session, selected: Option<usize>) {
    let n = session.visible_hops();
    // Prefer the clicked hop; otherwise fall back to the destination (last) hop.
    let idx = selected.filter(|&i| i < n).or_else(|| n.checked_sub(1));
    let Some(i) = idx else {
        ui.weak("No hops yet.");
        return;
    };

    let hop = &session.hops[i];
    let host = hop
        .meta
        .hostname
        .clone()
        .or_else(|| hop.primary_addr().map(|a| a.to_string()))
        .unwrap_or_else(|| "*".to_string());

    ui.horizontal(|ui| {
        ui.strong(format!("Hop {}", i + 1));
        ui.label(host);
        if let Some(avg) = hop.stat.avg_ms() {
            ui.label(format!("avg {avg:.1}"));
        }
        if let Some(j) = hop.stat.stddev_ms() {
            ui.label(format!("· jitter {j:.1}"));
        }
        let pct = |label: &str, v: Option<f64>| {
            v.map(|x| format!("· {label} {x:.1}")).unwrap_or_default()
        };
        ui.label(pct("p50", hop.stat.p50_ms()));
        ui.label(pct("p95", hop.stat.p95_ms()));
        ui.label(pct("p99", hop.stat.p99_ms()));
        ui.weak("ms");
    });

    let width = ui.available_width().min(820.0);
    draw(ui, &hop.recent, egui::vec2(width, 80.0));
}

fn draw(ui: &mut egui::Ui, samples: &VecDeque<Option<f32>>, size: egui::Vec2) {
    let (rect, _resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3.0, ui.visuals().extreme_bg_color);

    if samples.len() < 2 {
        return;
    }

    // Scale to the largest observed RTT (floor of 1 ms to avoid div-by-zero).
    let max = samples.iter().filter_map(|o| *o).fold(1.0_f32, f32::max);
    let n = samples.len();

    let points: Vec<egui::Pos2> = samples
        .iter()
        .enumerate()
        .map(|(k, o)| {
            let x = rect.left() + rect.width() * (k as f32 / (n - 1) as f32);
            let v = o.unwrap_or(0.0); // a lost probe dips to the baseline
            let t = (v / max).clamp(0.0, 1.0);
            let y = rect.bottom() - 1.0 - (rect.height() - 2.0) * t;
            egui::pos2(x, y)
        })
        .collect();

    painter.add(egui::Shape::line(
        points,
        egui::Stroke::new(1.5, ui.visuals().hyperlink_color),
    ));
}
