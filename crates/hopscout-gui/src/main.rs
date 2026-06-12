//! hopscout GUI - an egui front-end over the same engine the CLI uses.
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
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopscout_core::{
    Alert, Baseline, Engine, EngineConfig, ProbeProtocol, ReportParams, Session, brand,
};
use hopscout_enrich::EnricherHandle;
use hopscout_net::{BackendError, make_factory, path_mtu, relaunch_elevated};

/// MTU probe result: None = still probing, Some(None) = no answer, Some(Some) = bytes.
type MtuSlot = Arc<Mutex<Option<Option<u16>>>>;

use theme::Theme;

fn main() -> eframe::Result<()> {
    let arg_target = std::env::args().nth(1);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 640.0])
            .with_min_inner_size([680.0, 420.0])
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
    mtu: MtuSlot,
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

/// Address family preference, mirroring the CLI's `-4`/`-6`.
#[derive(Clone, Copy, PartialEq)]
enum Family {
    Auto,
    V4,
    V6,
}

/// Report formats the Export menu can write.
#[derive(Clone, Copy)]
enum ExportFmt {
    Text,
    Json,
    Csv,
}

struct HopscoutApp {
    target_input: String,
    interval_ms: u64,
    timeout_ms: u64,
    max_hops: u8,
    first_ttl: u8,
    psize: usize,
    proto: ProbeProtocol,
    port: u16,
    flows: u8,
    family: Family,
    no_dns: bool,
    show_ips: bool,
    view: View,
    map_view: map::MapView,
    themes: Vec<Theme>,
    theme_idx: usize,
    applied_idx: Option<usize>,
    monitors: Vec<Monitor>,
    active: Option<usize>,
    error: Option<String>,
    needs_elevation: bool,
    show_about: bool,
    export_status: Option<String>,
}

impl HopscoutApp {
    fn new(arg_target: Option<String>) -> Self {
        let mut app = Self {
            target_input: arg_target.clone().unwrap_or_default(),
            interval_ms: 1000,
            timeout_ms: 1000,
            max_hops: 30,
            first_ttl: 1,
            psize: 32,
            proto: ProbeProtocol::Icmp,
            port: 443,
            flows: 1,
            family: Family::Auto,
            no_dns: false,
            show_ips: false,
            view: View::Table,
            map_view: map::MapView::default(),
            themes: theme::all(),
            theme_idx: 0,
            applied_idx: None,
            monitors: Vec::new(),
            active: None,
            error: None,
            needs_elevation: false,
            show_about: false,
            export_status: None,
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
        let Some(dest) = resolve(self.target_input.trim(), self.family) else {
            self.error = Some(format!(
                "could not resolve a matching address for '{}'",
                self.target_input.trim()
            ));
            return;
        };

        let mut config = EngineConfig::new(dest);
        config.interval = Duration::from_millis(self.interval_ms.max(1));
        config.timeout = Duration::from_millis(self.timeout_ms.max(50));
        config.max_hops = self.max_hops.max(1);
        config.first_ttl = self.first_ttl.clamp(1, config.max_hops);
        config.payload_size = self.psize;
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
                let enricher = hopscout_enrich::spawn_with(engine.session(), !self.no_dns);

                // Probe the path MTU in the background.
                let mtu: MtuSlot = Arc::new(Mutex::new(None));
                if let IpAddr::V4(v4) = dest {
                    let slot = Arc::clone(&mtu);
                    thread::spawn(move || {
                        let r = path_mtu(v4, Duration::from_millis(800)).ok().flatten();
                        *slot.lock().unwrap() = Some(r);
                    });
                } else {
                    *mtu.lock().unwrap() = Some(None);
                }

                self.monitors.push(Monitor {
                    engine,
                    _enricher: enricher,
                    label: self.target_input.trim().to_string(),
                    config,
                    selected: None,
                    baseline: None,
                    mtu,
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

    /// Write the active monitor's current report (text/JSON/CSV) to the user's
    /// Downloads folder, using the same generators as the CLI's `-r`/`-j`/`-C`.
    fn export(&mut self, fmt: ExportFmt) {
        let Some(active) = self.active else {
            self.export_status = Some("No active target to export.".to_string());
            return;
        };
        // Build everything from the monitor inside a scope so its borrow ends
        // before we write back to self.export_status.
        let (body, ext, safe) = {
            let mon = &self.monitors[active];
            let snap = mon.engine.snapshot();
            let label = mon.label.clone();
            let params = ReportParams {
                target: label.clone(),
                first_ttl: mon.config.first_ttl,
                psize: mon.config.payload_size,
                cycles: 0,
                wide: true,
                no_dns: self.no_dns,
                show_ips: self.show_ips,
                mpls: true,
                fields: hopscout_core::fields::default(),
            };
            let (body, ext) = match fmt {
                ExportFmt::Text => (hopscout_core::report::text(&snap, &params), "txt"),
                ExportFmt::Json => (hopscout_core::report::json(&snap, &params), "json"),
                ExportFmt::Csv => (hopscout_core::report::csv(&snap, &params), "csv"),
            };
            let safe: String = label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
                .collect();
            (body, ext, safe)
        };

        let dir = directories::UserDirs::new()
            .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
            .unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!("hopscout-{safe}.{ext}"));
        self.export_status = Some(match std::fs::write(&path, body) {
            Ok(()) => format!("Saved {}", path.display()),
            Err(e) => format!("Export failed: {e}"),
        });
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

            // Controls wrap onto extra rows on narrow windows instead of clipping.
            ui.horizontal_wrapped(|ui| {
                ui.label("Target");
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.target_input)
                        .desired_width(150.0)
                        .hint_text("host or IP"),
                );
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                egui::ComboBox::from_id_salt("family")
                    .selected_text(family_label(self.family))
                    .width(64.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.family, Family::Auto, "Auto");
                        ui.selectable_value(&mut self.family, Family::V4, "IPv4");
                        ui.selectable_value(&mut self.family, Family::V6, "IPv6");
                    })
                    .response
                    .on_hover_text("address family (Auto prefers IPv4)");

                egui::ComboBox::from_id_salt("proto")
                    .selected_text(proto_label(self.proto))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.proto, ProbeProtocol::Icmp, "ICMP");
                        ui.selectable_value(&mut self.proto, ProbeProtocol::Udp, "UDP (admin)");
                        ui.selectable_value(&mut self.proto, ProbeProtocol::TcpSyn, "TCP (Npcap)");
                    })
                    .response
                    .on_hover_text("ICMP needs no admin; UDP/TCP elevate on demand");
                if self.proto == ProbeProtocol::TcpSyn {
                    ui.add(egui::DragValue::new(&mut self.port).prefix("port ").range(1..=65535));
                }
                ui.add(egui::DragValue::new(&mut self.interval_ms).suffix(" ms").range(1..=60_000))
                    .on_hover_text("interval between probes");
                ui.add(egui::DragValue::new(&mut self.timeout_ms).prefix("⏱ ").suffix(" ms").range(50..=60_000))
                    .on_hover_text("per-probe timeout");
                ui.add(egui::DragValue::new(&mut self.max_hops).prefix("hops ").range(1..=64))
                    .on_hover_text("max TTL");
                ui.add(egui::DragValue::new(&mut self.first_ttl).prefix("from ").range(1..=64))
                    .on_hover_text("first TTL (start hop)");
                ui.add(egui::DragValue::new(&mut self.psize).prefix("size ").range(0..=65500))
                    .on_hover_text("payload bytes");
                ui.add(egui::DragValue::new(&mut self.flows).prefix("flows ").range(1..=8))
                    .on_hover_text("concurrent flows for multipath discovery");
                ui.checkbox(&mut self.no_dns, "no DNS").on_hover_text("don't resolve host names");
                ui.checkbox(&mut self.show_ips, "IPs").on_hover_text("show IPs alongside names");

                if ui.button("Add target").clicked() || enter {
                    self.add_target();
                }
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
            });

            ui.add_space(2.0);

            // View tabs on the left, theme + About on the right (wraps if narrow).
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut self.view, View::Table, "Table");
                ui.selectable_value(&mut self.view, View::Map, "Map");
                ui.selectable_value(&mut self.view, View::Topology, "Topology");
                ui.selectable_value(&mut self.view, View::Alerts, "Alerts");

                ui.separator();
                ui.menu_button("Export", |ui| {
                    if ui.button("Text report (.txt)").clicked() {
                        self.export(ExportFmt::Text);
                        ui.close();
                    }
                    if ui.button("JSON (.json)").clicked() {
                        self.export(ExportFmt::Json);
                        ui.close();
                    }
                    if ui.button("CSV (.csv)").clicked() {
                        self.export(ExportFmt::Csv);
                        ui.close();
                    }
                })
                .response
                .on_hover_text("Save the active target's report to your Downloads folder");

                ui.separator();
                let cur = self.themes.get(self.theme_idx).map(|t| t.name.as_str()).unwrap_or("Theme");
                egui::ComboBox::from_id_salt("theme")
                    .selected_text(cur)
                    .show_ui(ui, |ui| {
                        for (i, t) in self.themes.iter().enumerate() {
                            ui.selectable_value(&mut self.theme_idx, i, &t.name);
                        }
                    });
                if ui.button("⟳").on_hover_text("Reload custom themes from disk").clicked() {
                    let keep = self.themes.get(self.theme_idx).map(|t| t.name.clone());
                    self.themes = theme::all();
                    self.theme_idx = keep
                        .and_then(|n| self.themes.iter().position(|t| t.name == n))
                        .unwrap_or(0);
                    self.applied_idx = None;
                }
                if ui.button("About").clicked() {
                    self.show_about = true;
                }
                if let Some(s) = self.export_status.clone() {
                    ui.separator();
                    ui.weak(s.clone()).on_hover_text(s);
                }
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
                        let short = truncate_label(&mon.label, 18);
                        if ui
                            .selectable_label(selected, short)
                            .on_hover_text(&mon.label)
                            .clicked()
                        {
                            select = Some(i);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("✕").on_hover_text("Remove").clicked() {
                                remove = Some(i);
                            }
                        });
                    });
                    let avg = dest_avg.map(|v| format!("{v:.0}ms")).unwrap_or_else(|| "-".into());
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
            let mtu_text = mtu_label(&self.monitors[active].mtu);
            ui.horizontal_wrapped(|ui| {
                ui.strong(label);
                ui.label(format!("({target})"));
                match snapshot.path_len {
                    Some(p) => ui.label(format!("· destination at hop {p}")),
                    None => ui.label("· discovering path…"),
                };
                ui.label(format!("· {mtu_text}"));
            });
            ui.separator();

            match self.view {
                View::Table => {
                    let show_ips = self.show_ips;
                    let no_dns = self.no_dns;
                    let selected = &mut self.monitors[active].selected;
                    table::show(ui, &snapshot, selected, &theme, show_ips, no_dns);
                    ui.separator();
                    sparkline::panel(ui, &snapshot, *selected);
                }
                View::Map => map::show(ui, &snapshot, &theme, &mut self.map_view),
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
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    for d in &devs {
                                        ui.colored_label(alert_color(d, &theme), d.message());
                                    }
                                });
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

fn truncate_label(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn mtu_label(slot: &MtuSlot) -> String {
    match *slot.lock().unwrap() {
        None => "MTU probing…".to_string(),
        Some(None) => "MTU n/a".to_string(),
        Some(Some(m)) => format!("MTU {m}"),
    }
}

fn proto_label(p: ProbeProtocol) -> &'static str {
    match p {
        ProbeProtocol::Icmp => "ICMP",
        ProbeProtocol::Udp => "UDP",
        ProbeProtocol::TcpSyn => "TCP",
    }
}

fn family_label(f: Family) -> &'static str {
    match f {
        Family::Auto => "Auto",
        Family::V4 => "IPv4",
        Family::V6 => "IPv6",
    }
}

/// Resolve a host or literal to an address, honoring the family preference
/// (Auto prefers IPv4 then falls back to IPv6).
fn resolve(target: &str, family: Family) -> Option<IpAddr> {
    if target.is_empty() {
        return None;
    }
    let matches = |a: &IpAddr| match family {
        Family::Auto => true,
        Family::V4 => a.is_ipv4(),
        Family::V6 => a.is_ipv6(),
    };
    if let Ok(ip) = target.parse::<IpAddr>() {
        return matches(&ip).then_some(ip);
    }
    let mut addrs: Vec<IpAddr> = (target, 0u16)
        .to_socket_addrs()
        .ok()?
        .map(|s| s.ip())
        .filter(matches)
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs.into_iter().next()
}
