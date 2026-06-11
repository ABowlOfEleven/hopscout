//! Equirectangular world-map view: hops with geolocation plotted by lat/lon,
//! connected in path order and labeled with city + TTL. A graticule stands in
//! for coastlines (no map asset needed).

use hopscout_core::Session;

const BG: egui::Color32 = egui::Color32::from_rgb(18, 24, 34);
const GRID: egui::Color32 = egui::Color32::from_rgb(34, 44, 58);
const EQUATOR: egui::Color32 = egui::Color32::from_rgb(48, 60, 76);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(57, 217, 138);
const LABEL: egui::Color32 = egui::Color32::from_rgb(205, 214, 224);

pub fn show(ui: &mut egui::Ui, session: &Session) {
    let size = egui::vec2(ui.available_width(), ui.available_height().max(240.0));
    let (rect, _resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, BG);

    // Graticule: meridians every 30°, parallels every 30°, equator emphasized.
    let grid = egui::Stroke::new(1.0, GRID);
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
        egui::Stroke::new(1.0, EQUATOR),
    );

    let project = |lat: f32, lon: f32| {
        egui::pos2(
            rect.left() + rect.width() * ((lon + 180.0) / 360.0),
            rect.top() + rect.height() * ((90.0 - lat) / 180.0),
        )
    };

    // Geolocated hops in path order.
    let mut pts: Vec<(egui::Pos2, String, usize)> = Vec::new();
    for i in 0..session.visible_hops() {
        let hop = &session.hops[i];
        if let (Some(lat), Some(lon)) = (hop.meta.lat, hop.meta.lon) {
            let city = hop.meta.city.clone().unwrap_or_default();
            pts.push((project(lat, lon), city, i + 1));
        }
    }

    // Path arcs between consecutive located hops.
    let line = egui::Stroke::new(1.5, ACCENT);
    for w in pts.windows(2) {
        painter.line_segment([w[0].0, w[1].0], line);
    }

    // Nodes + labels.
    let font = egui::FontId::proportional(11.0);
    for (pos, city, ttl) in &pts {
        painter.circle_filled(*pos, 4.0, ACCENT);
        let text = if city.is_empty() {
            ttl.to_string()
        } else {
            format!("{ttl} · {city}")
        };
        painter.text(
            *pos + egui::vec2(7.0, -2.0),
            egui::Align2::LEFT_CENTER,
            text,
            font.clone(),
            LABEL,
        );
    }

    if pts.is_empty() {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Waiting for geolocation…",
            egui::FontId::proportional(14.0),
            egui::Color32::GRAY,
        );
    }
}
