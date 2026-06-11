//! hopscout GUI — an egui front-end over the same engine the CLI uses.
//!
//! Enter a target, Start, and watch the live hop table (loss/RTT/jitter, with
//! reverse-DNS and ASN filled in by the background enricher). Click a hop to see
//! its recent-RTT sparkline.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sparkline;
mod table;

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use hopscout_core::{Engine, EngineConfig, brand};
use hopscout_enrich::EnricherHandle;
use hopscout_net::IcmpBackendFactory;

fn main() -> eframe::Result<()> {
    let arg_target = std::env::args().nth(1);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
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

/// A live trace: the engine, its enricher, and display state.
struct Running {
    engine: Engine,
    _enricher: EnricherHandle,
    label: String,
    config: EngineConfig,
}

impl Running {
    fn stop(self) {
        // Drop order: stop the enricher, then join the engine workers.
        self._enricher.stop();
        self.engine.stop();
    }
}

struct HopscoutApp {
    target_input: String,
    interval_ms: u64,
    max_hops: u8,
    running: Option<Running>,
    selected: Option<usize>,
    error: Option<String>,
    show_about: bool,
}

impl HopscoutApp {
    fn new(arg_target: Option<String>) -> Self {
        let mut app = Self {
            target_input: arg_target.clone().unwrap_or_default(),
            interval_ms: 1000,
            max_hops: 30,
            running: None,
            selected: None,
            error: None,
            show_about: false,
        };
        if arg_target.is_some() {
            app.start();
        }
        app
    }

    fn start(&mut self) {
        self.error = None;
        let Some(dest) = resolve(self.target_input.trim()) else {
            self.error = Some(format!(
                "could not resolve an IPv4 address for '{}'",
                self.target_input.trim()
            ));
            return;
        };

        let mut config = EngineConfig::new(dest);
        config.interval = Duration::from_millis(self.interval_ms.max(1));
        config.max_hops = self.max_hops.max(1);

        match Engine::start(config.clone(), Arc::new(IcmpBackendFactory)) {
            Ok(engine) => {
                let enricher = hopscout_enrich::spawn(engine.session());
                self.selected = None;
                self.running = Some(Running {
                    engine,
                    _enricher: enricher,
                    label: self.target_input.trim().to_string(),
                    config,
                });
            }
            Err(e) => self.error = Some(format!("failed to start engine: {e}")),
        }
    }

    fn stop(&mut self) {
        if let Some(run) = self.running.take() {
            run.stop();
        }
    }
}

impl eframe::App for HopscoutApp {
    // This eframe builds the root viewport into a `Ui`; panels nest via
    // `show_inside`, and the context comes from `ui.ctx()`.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Keep the live view ticking even without input events.
        if self.running.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(150));
        }

        egui::Panel::top("controls").show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Target:");
                let enter = ui
                    .text_edit_singleline(&mut self.target_input)
                    .lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                let running = self.running.is_some();
                ui.add_enabled_ui(!running, |ui| {
                    ui.label("interval");
                    ui.add(egui::DragValue::new(&mut self.interval_ms).suffix(" ms").range(1..=60_000));
                    ui.label("max hops");
                    ui.add(egui::DragValue::new(&mut self.max_hops).range(1..=64));
                });

                if running {
                    if ui.button("Stop").clicked() {
                        self.stop();
                    }
                    if let Some(run) = &self.running {
                        let paused = run.engine.is_paused();
                        if ui.button(if paused { "Resume" } else { "Pause" }).clicked() {
                            run.engine.toggle_pause();
                        }
                        if ui.button("Reset").clicked() {
                            run.engine.reset();
                        }
                    }
                } else if ui.button("Start").clicked() || enter {
                    self.start();
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            if let Some(err) = &self.error {
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
                ui.separator();
            }

            let Some(run) = &self.running else {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.heading("hopscout");
                    ui.label("Enter a target host and press Start.");
                });
                return;
            };

            let snapshot = run.engine.snapshot();
            ui.horizontal(|ui| {
                ui.strong(&run.label);
                ui.label(format!("({})", run.config.target));
                match snapshot.path_len {
                    Some(p) => ui.label(format!("· destination at hop {p}")),
                    None => ui.label("· discovering path…"),
                };
            });
            ui.separator();

            table::show(ui, &snapshot, &mut self.selected);

            ui.separator();
            sparkline::panel(ui, &snapshot, self.selected);
        });

        if self.show_about {
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
                    ui.label("Rung-1 ICMP needs no admin; UDP (rung 2) needs elevation.");
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        self.show_about = false;
                    }
                });
        }
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
