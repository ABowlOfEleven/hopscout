//! Equirectangular world-map view: coastlines (if the asset is present) plus
//! hops plotted by lat/lon, connected in path order and labeled with city + TTL.

use hopscout_core::Session;

use crate::coastline;
use crate::theme::Theme;

pub fn show(ui: &mut egui::Ui, session: &Session, theme: &Theme) {
    let size = egui::vec2(ui.available_width(), ui.available_height().max(240.0));
    let (rect, _resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, theme.surface);

    let project = |lat: f32, lon: f32| {
        egui::pos2(
            rect.left() + rect.width() * ((lon + 180.0) / 360.0),
            rect.top() + rect.height() * ((90.0 - lat) / 180.0),
        )
    };

    // Coastlines under everything.
    let coast = egui::Stroke::new(1.0, theme.grid.gamma_multiply(1.6));
    for stroke_pts in coastline::polylines() {
        let pts: Vec<egui::Pos2> = stroke_pts.iter().map(|&(lon, lat)| project(lat, lon)).collect();
        if pts.len() >= 2 {
            painter.add(egui::Shape::line(pts, coast));
        }
    }

    // Graticule + equator.
    let grid = egui::Stroke::new(1.0, theme.grid);
    for k in 1..12 {
        let x = rect.left() + rect.width() * (k as f32 / 12.0);
        painter.line_segment([egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())], grid);
    }
    for k in 1..6 {
        let y = rect.top() + rect.height() * (k as f32 / 6.0);
        painter.line_segment([egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)], grid);
    }
    let mid = rect.top() + rect.height() * 0.5;
    painter.line_segment(
        [egui::pos2(rect.left(), mid), egui::pos2(rect.right(), mid)],
        egui::Stroke::new(1.0, theme.muted.gamma_multiply(0.6)),
    );

    // Geolocated hops in path order.
    let mut pts: Vec<(egui::Pos2, String, usize)> = Vec::new();
    for i in 0..session.visible_hops() {
        let hop = &session.hops[i];
        if let (Some(lat), Some(lon)) = (hop.meta.lat, hop.meta.lon) {
            let city = hop.meta.city.clone().unwrap_or_default();
            pts.push((project(lat, lon), city, i + 1));
        }
    }

    let line = egui::Stroke::new(1.5, theme.accent);
    for w in pts.windows(2) {
        painter.line_segment([w[0].0, w[1].0], line);
    }

    let font = egui::FontId::proportional(11.0);
    for (pos, city, ttl) in &pts {
        painter.circle_filled(*pos, 4.0, theme.accent);
        let text = if city.is_empty() {
            ttl.to_string()
        } else {
            format!("{ttl} · {city}")
        };
        painter.text(*pos + egui::vec2(7.0, -2.0), egui::Align2::LEFT_CENTER, text, font.clone(), theme.text);
    }

    if pts.is_empty() {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Waiting for geolocation…",
            egui::FontId::proportional(14.0),
            theme.muted,
        );
    }
}
