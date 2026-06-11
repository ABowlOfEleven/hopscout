//! Equirectangular world-map view with scroll-to-zoom and drag-to-pan.
//! Coastlines (embedded asset) plus hops plotted by lat/lon, connected in path
//! order and labeled with city + TTL.

use hopscout_core::Session;

use crate::coastline;
use crate::theme::Theme;

/// Persistent pan/zoom state for the map (center in degrees, zoom factor).
#[derive(Clone, Copy)]
pub struct MapView {
    pub center: (f32, f32), // (lon, lat)
    pub zoom: f32,
}

impl Default for MapView {
    fn default() -> Self {
        Self { center: (0.0, 20.0), zoom: 1.0 }
    }
}

fn scale(rect: egui::Rect, zoom: f32) -> (f32, f32) {
    (rect.width() / 360.0 * zoom, rect.height() / 180.0 * zoom)
}

fn unproject(p: egui::Pos2, rect: egui::Rect, view: &MapView) -> (f32, f32) {
    let (sx, sy) = scale(rect, view.zoom);
    (
        view.center.0 + (p.x - rect.center().x) / sx,
        view.center.1 - (p.y - rect.center().y) / sy,
    )
}

pub fn show(ui: &mut egui::Ui, session: &Session, theme: &Theme, view: &mut MapView) {
    let size = egui::vec2(ui.available_width(), ui.available_height().max(240.0));
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, theme.surface);

    // --- interaction: drag = pan, scroll = zoom-at-cursor, double-click = reset.
    if resp.double_clicked() {
        *view = MapView::default();
    }
    if resp.dragged() {
        let d = resp.drag_delta();
        let (sx, sy) = scale(rect, view.zoom);
        view.center.0 -= d.x / sx;
        view.center.1 += d.y / sy;
    }
    if resp.hovered() {
        let sd = ui.input(|i| i.smooth_scroll_delta.y);
        if sd.abs() > 0.0 {
            let factor = (sd * 0.0015).exp();
            if let Some(cursor) = resp.hover_pos() {
                let before = unproject(cursor, rect, view);
                view.zoom = (view.zoom * factor).clamp(0.4, 40.0);
                let after = unproject(cursor, rect, view);
                view.center.0 += before.0 - after.0;
                view.center.1 += before.1 - after.1;
            } else {
                view.zoom = (view.zoom * factor).clamp(0.4, 40.0);
            }
        }
    }
    view.center.1 = view.center.1.clamp(-85.0, 85.0);

    let project = |lon: f32, lat: f32| {
        let (sx, sy) = scale(rect, view.zoom);
        egui::pos2(
            rect.center().x + (lon - view.center.0) * sx,
            rect.center().y - (lat - view.center.1) * sy,
        )
    };

    // Coastlines.
    let coast = egui::Stroke::new(1.0, theme.grid.gamma_multiply(1.7));
    for poly in coastline::polylines() {
        let pts: Vec<egui::Pos2> = poly.iter().map(|&(lon, lat)| project(lon, lat)).collect();
        if pts.len() >= 2 {
            painter.add(egui::Shape::line(pts, coast));
        }
    }

    // Graticule (every 30 deg) + equator.
    let grid = egui::Stroke::new(1.0, theme.grid);
    let mut lon = -180.0;
    while lon <= 180.0 {
        painter.line_segment([project(lon, -85.0), project(lon, 85.0)], grid);
        lon += 30.0;
    }
    let mut lat = -60.0;
    while lat <= 60.0 {
        let s = if lat == 0.0 {
            egui::Stroke::new(1.0, theme.muted.gamma_multiply(0.6))
        } else {
            grid
        };
        painter.line_segment([project(-180.0, lat), project(180.0, lat)], s);
        lat += 30.0;
    }

    // Geolocated hops in path order.
    let mut pts: Vec<(egui::Pos2, String, usize)> = Vec::new();
    for i in 0..session.visible_hops() {
        let hop = &session.hops[i];
        if let (Some(la), Some(lo)) = (hop.meta.lat, hop.meta.lon) {
            let city = hop.meta.city.clone().unwrap_or_default();
            pts.push((project(lo, la), city, i + 1));
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

    painter.text(
        rect.left_bottom() + egui::vec2(6.0, -6.0),
        egui::Align2::LEFT_BOTTOM,
        "scroll: zoom · drag: pan · double-click: reset",
        egui::FontId::proportional(10.0),
        theme.muted,
    );
}
