//! hopscout GUI — an egui front-end over the same engine the CLI uses.
//!
//! Multi-target: add several destinations and monitor them side by side. The
//! left panel lists them with a live summary; the selected one drives the
//! Table / Map / Topology views.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod coastline;
mod map;
mod sparkline;
mod table;
mod theme;
mod topo;

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use hopscout_core::{Alert, Baseline, Engine, EngineConfig, ProbeProtocol, Session, brand};
use hopscout_enrich::EnricherHandle;
use hopscout_net::{BackendError, make_factory, relaunch_elevated};

use theme::Theme;

fn main() -> eframe::Result<()> {
    let arg_target = std::env::args().nth(1);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 640.0])
            .with_title(brand::name_version())
            .with_app_id("hopscout"),
        ..Default::default()
    };
    eframe::run_native(
        brand::NAME,
        options,
        Box::new(|_cc| Ok(Box::new(HopscoutApp::new(arg_target)))),
    )
}

/// One monitored target: its engine, enricher, and per-target UI state.
struct Monitor {
    engine: Engine,
    _enricher: EnricherHandle,
    label: String,
    config: EngineConfig,
    selected: Option<usize>,
    baseline: Option<Baseline>,
}

impl Monitor {
    fn stop(self) {
        // Drop order: stop the enricher, then join the engine workers.
        self._enricher.stop();
        self.engine.stop();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    Table,
    Map,
    Topology,
    Alerts,
}

struct HopscoutApp {
    target_input: String,
    interval_ms: u64,
    max_hops: u8,
    proto: ProbeProtocol,
    port: u16,
    flows: u8,
    view: View,
    themes: Vec<Theme>,
    theme_idx: usize,
    applied_idx: Option<usize>,
    monitors: Vec<Monitor>,
    active: Option<usize>,
    error: Option<String>,
    needs_elevation: bool,
    show_about: bool,
}

impl HopscoutApp {
    fn new(arg_target: Option<String>) -> Self {
        let mut app = Self {
            target_input: arg_target.clone().unwrap_or_default(),
            interval_ms: 1000,
            max_hops: 30,
            proto: ProbeProtocol::Icmp,
            port: 443,
            flows: 1,
            view: View::Table,
            themes: theme::all(),
            theme_idx: 0,
            applied_idx: None,
            monitors: Vec::new(),
            active: None,
            error: None,
            needs_elevation: false,
            show_about: false,
        };
        if arg_target.is_some() {
            app.add_target();
        }
        app
    }

    /// Build a monitor for the current target field + settings and select it.
    fn add_target(&mut self) {
        self.error = None;
        self.needs_elevation = false;
        let Some(dest) = resolve(self.target_input.trim()) else {
            self.error = Some(format!(
                "could not resolve an address for '{}'",
                self.target_input.trim()
            ));
            return;
        };

        let mut config = EngineConfig::new(dest);
        config.interval = Duration::from_millis(self.interval_ms.max(1));
        config.max_hops = self.max_hops.max(1);
        config.protocol = self.proto;
        config.flows = self.flows.max(1);

        let factory = match make_factory(self.proto, dest, self.port) {
            Ok(f) => f,
            Err(BackendError::NeedsElevation) => {
                self.error = Some("This mode needs administrator privileges.".to_string());
                self.needs_elevation = true;
                return;
            }
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };

        match Engine::start(config.clone(), factory) {
            Ok(engine) => {
                let enricher = hopscout_enrich::spawn(engine.session());
                self.monitors.push(Monitor {
                    engine,
                    _enricher: enricher,
                    label: self.target_input.trim().to_string(),
                    config,
                    selected: None,
                    baseline: None,
                });
                self.active = Some(self.monitors.len() - 1);
            }
            Err(e) => self.error = Some(format!("failed to start engine: {e}")),
        }
    }

    fn remove(&mut self, idx: usize) {
        if idx >= self.monitors.len() {
            return;
        }
        self.monitors.remove(idx).stop();
        self.active = if self.monitors.is_empty() {
            None
        } else {
            Some(self.active.unwrap_or(0).min(self.monitors.len() - 1))
        };
    }
}

impl eframe::App for HopscoutApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.monitors.is_empty() {
            ui.ctx().request_repaint_after(Duration::from_millis(150));
        }

        // Apply the active theme on first frame and whenever it changes.
        if self.applied_idx != Some(self.theme_idx) {
            if self.theme_idx >= self.themes.len() {
                self.theme_idx = 0;
            }
            self.themes[self.theme_idx].apply(ui.ctx());
            self.applied_idx = Some(self.theme_idx);
        }

        self.top_bar(ui);
        self.monitor_list(ui);
        self.main_view(ui);
        self.about_window(ui);
    }
}

impl HopscoutApp {
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("controls").show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Target:");
                let enter = ui.text_edit_singleline(&mut self.target_input).lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                ui.label("proto");
                egui::ComboBox::from_id_salt("proto")
                    .selected_text(proto_label(self.proto))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.proto, ProbeProtocol::Icmp, "ICMP");
                        ui.selectable_value(&mut self.proto, ProbeProtocol::Udp, "UDP");
                        ui.selectable_value(&mut self.proto, ProbeProtocol::TcpSyn, "TCP");
                    });
                if self.proto == ProbeProtocol::TcpSyn {
                    ui.label("port");
                    ui.add(egui::DragValue::new(&mut self.port).range(1..=65535));
                }
                ui.label("interval");
                ui.add(egui::DragValue::new(&mut self.interval_ms).suffix(" ms").range(1..=60_000));
                ui.label("hops");
                ui.add(egui::DragValue::new(&mut self.max_hops).range(1..=64));
                ui.label("flows");
                ui.add(egui::DragValue::new(&mut self.flows).range(1..=8));

                if ui.button("Add target").clicked() || enter {
                    self.add_target();
                }

                // Per-active controls.
                if let Some(active) = self.active {
                    let mon = &self.monitors[active];
                    let paused = mon.engine.is_paused();
                    if ui.button(if paused { "Resume" } else { "Pause" }).clicked() {
                        mon.engine.toggle_pause();
                    }
                    if ui.button("Reset").clicked() {
                        mon.engine.reset();
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                    if ui.button("⟳").on_hover_text("Reload custom themes").clicked() {
                        let keep = self.themes.get(self.theme_idx).map(|t| t.name.clone());
                        self.themes = theme::all();
                        self.theme_idx = keep
                            .and_then(|n| self.themes.iter().position(|t| t.name == n))
                            .unwrap_or(0);
                        self.applied_idx = None;
                    }
                    let cur = self.themes.get(self.theme_idx).map(|t| t.name.as_str()).unwrap_or("Theme");
                    egui::ComboBox::from_id_salt("theme")
                        .selected_text(cur)
                        .show_ui(ui, |ui| {
                            for (i, t) in self.themes.iter().enumerate() {
                                ui.selectable_value(&mut self.theme_idx, i, &t.name);
                            }
                        });
                });
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, View::Table, "Table");
                ui.selectable_value(&mut self.view, View::Map, "Map");
                ui.selectable_value(&mut self.view, View::Topology, "Topology");
                ui.selectable_value(&mut self.view, View::Alerts, "Alerts");
            });
            ui.add_space(4.0);
        });
    }

    fn monitor_list(&mut self, ui: &mut egui::Ui) {
        if self.monitors.is_empty() {
            return;
        }
        let mut select: Option<usize> = None;
        let mut remove: Option<usize> = None;
        egui::Panel::left("monitors")
            .resizable(true)
            .default_size(190.0)
            .show_inside(ui, |ui| {
                ui.add_space(4.0);
                ui.strong("Targets");
                ui.separator();
                for (i, mon) in self.monitors.iter().enumerate() {
                    let s = mon.engine.snapshot();
                    let (hops, worst, dest_avg) = summary(&s);
                    let selected = self.active == Some(i);
                    ui.horizontal(|ui| {
                        if ui.selectable_label(selected, &mon.label).clicked() {
                            select = Some(i);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("✕").clicked() {
                                remove = Some(i);
                            }
                        });
                    });
                    let avg = dest_avg.map(|v| format!("{v:.0}ms")).unwrap_or_else(|| "—".into());
                    ui.weak(format!("{hops} hops · loss {worst:.0}% · {avg}"));
                    ui.add_space(4.0);
                }
            });
        if let Some(i) = select {
            self.active = Some(i);
        }
        if let Some(i) = remove {
            self.remove(i);
        }
    }

    fn main_view(&mut self, ui: &mut egui::Ui) {
        let theme = self.themes[self.theme_idx.min(self.themes.len() - 1)].clone();
        egui::CentralPanel::default().show_inside(ui, |ui| {
            if let Some(err) = self.error.clone() {
                ui.colored_label(theme.bad, &err);
                if self.needs_elevation && ui.button("Relaunch as administrator").clicked() {
                    let _ = relaunch_elevated();
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ui.separator();
            }

            let Some(active) = self.active else {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.heading("hopscout");
                    ui.label("Enter a target host and press Add target.");
                });
                return;
            };

            let snapshot = self.monitors[active].engine.snapshot();
            let label = self.monitors[active].label.clone();
            let target = self.monitors[active].config.target;
            ui.horizontal(|ui| {
                ui.strong(label);
                ui.label(format!("({target})"));
                match snapshot.path_len {
                    Some(p) => ui.label(format!("· destination at hop {p}")),
                    None => ui.label("· discovering path…"),
                };
            });
            ui.separator();

            match self.view {
                View::Table => {
                    let selected = &mut self.monitors[active].selected;
                    table::show(ui, &snapshot, selected, &theme);
                    ui.separator();
                    sparkline::panel(ui, &snapshot, *selected);
                }
                View::Map => map::show(ui, &snapshot, &theme),
                View::Topology => topo::show(ui, &snapshot, &theme),
                View::Alerts => {
                    let mon = &mut self.monitors[active];
                    ui.horizontal(|ui| {
                        if ui.button("Set baseline").clicked() {
                            mon.baseline = Some(Baseline::capture(&snapshot));
                        }
                        if mon.baseline.is_some() && ui.button("Clear").clicked() {
                            mon.baseline = None;
                        }
                    });
                    ui.separator();
                    match &mon.baseline {
                        None => {
                            ui.weak("No baseline captured. Set one to watch for route changes, latency regressions, and loss.");
                        }
                        Some(b) => {
                            let devs = b.deviations(&snapshot, 1.5);
                            if devs.is_empty() {
                                ui.colored_label(theme.good, "✓ path matches baseline");
                            } else {
                                for d in &devs {
                                    ui.colored_label(alert_color(d, &theme), d.message());
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    fn about_window(&mut self, ui: &mut egui::Ui) {
        if !self.show_about {
            return;
        }
        let ctx = ui.ctx().clone();
        egui::Window::new("About")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(&ctx, |ui| {
                ui.heading(brand::DISPLAY_NAME);
                ui.label(brand::name_version());
                ui.label(brand::TAGLINE);
                ui.add_space(6.0);
                ui.hyperlink(brand::REPOSITORY);
                ui.add_space(6.0);
                ui.label("Rung-1 ICMP needs no admin; UDP/TCP need elevation.");
                ui.add_space(8.0);
                if ui.button("Close").clicked() {
                    self.show_about = false;
                }
            });
    }
}

/// (visible hop count, worst hop loss %, destination avg RTT) for the sidebar.
fn summary(s: &Session) -> (usize, f64, Option<f64>) {
    let n = s.visible_hops();
    let mut worst = 0.0_f64;
    for i in 0..n {
        worst = worst.max(s.hops[i].stat.loss_pct());
    }
    let dest_avg = if n > 0 { s.hops[n - 1].stat.avg_ms() } else { None };
    (n, worst, dest_avg)
}

fn alert_color(a: &Alert, theme: &Theme) -> egui::Color32 {
    match a {
        Alert::RouteChanged { .. } | Alert::HopAppeared { .. } | Alert::HopDisappeared { .. } => {
            theme.warn // route shifts
        }
        Alert::LatencyRegression { .. } | Alert::LossOnset { .. } => {
            theme.bad // degradation
        }
    }
}

fn proto_label(p: ProbeProtocol) -> &'static str {
    match p {
        ProbeProtocol::Icmp => "ICMP",
        ProbeProtocol::Udp => "UDP",
        ProbeProtocol::TcpSyn => "TCP",
    }
}

/// Resolve a host or literal to an address (prefers IPv4, falls back to IPv6).
fn resolve(target: &str) -> Option<IpAddr> {
    if target.is_empty() {
        return None;
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }
    let mut addrs: Vec<IpAddr> = (target, 0u16).to_socket_addrs().ok()?.map(|s| s.ip()).collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs.into_iter().next()
}
