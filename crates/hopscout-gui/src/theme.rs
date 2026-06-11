//! Theming. A [`Theme`] is a flat palette consumed both by egui (window/panel/
//! widget styling) and by the custom-painted views (map, topology, sparkline).
//! Several themes ship built in; users can drop their own `*.toml` palettes into
//! the config folder and load them at runtime.

use std::path::PathBuf;

use egui::Color32;
use serde::Deserialize;

/// A complete palette + a couple of style flags.
#[derive(Clone)]
pub struct Theme {
    pub name: String,
    pub dark: bool,
    pub bg: Color32,
    pub panel: Color32,
    pub surface: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent2: Color32,
    pub good: Color32,
    pub warn: Color32,
    pub bad: Color32,
    pub grid: Color32,
    pub flow: [Color32; 6],
}

fn hex(s: &str) -> Color32 {
    let s = s.trim().trim_start_matches('#');
    let n = u32::from_str_radix(s, 16).unwrap_or(0);
    if s.len() == 8 {
        Color32::from_rgba_unmultiplied(
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        )
    } else {
        Color32::from_rgb((n >> 16) as u8, (n >> 8) as u8, n as u8)
    }
}

impl Theme {
    /// Loss color: good / warn / bad.
    pub fn loss(&self, pct: f64) -> Color32 {
        if pct <= 0.0 {
            self.good
        } else if pct < 5.0 {
            self.warn
        } else {
            self.bad
        }
    }

    pub fn flow_color(&self, i: usize) -> Color32 {
        self.flow[i % self.flow.len()]
    }

    /// Apply this theme + a modern base style to the egui context.
    pub fn apply(&self, ctx: &egui::Context) {
        let mut v = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        v.override_text_color = Some(self.text);
        v.hyperlink_color = self.accent;
        v.window_fill = self.bg;
        v.panel_fill = self.panel;
        v.extreme_bg_color = self.surface;
        v.faint_bg_color = self.panel;
        v.selection.bg_fill = self.accent.gamma_multiply(0.45);
        v.selection.stroke = egui::Stroke::new(1.0, self.accent);
        v.widgets.noninteractive.bg_fill = self.panel;
        v.widgets.inactive.bg_fill = self.surface;
        v.widgets.hovered.bg_fill = self.panel.gamma_multiply(1.4);
        v.widgets.active.bg_fill = self.accent.gamma_multiply(0.6);
        v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, self.text);
        v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, self.muted);

        let mut style = (*ctx.global_style()).clone();
        style.visuals = v;
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(9.0, 4.0);
        style.spacing.window_margin = egui::Margin::same(10);
        ctx.set_global_style(style);
    }
}

/// All available themes: built-ins followed by any user `*.toml` palettes.
pub fn all() -> Vec<Theme> {
    let mut v = builtins();
    v.extend(load_custom());
    v
}

/// The built-in themes, in selector order. The first is the default.
pub fn builtins() -> Vec<Theme> {
    vec![
        Theme {
            name: "Midnight".into(),
            dark: true,
            bg: hex("#12161f"),
            panel: hex("#1a2230"),
            surface: hex("#0d121b"),
            text: hex("#cdd6e0"),
            muted: hex("#7a8694"),
            accent: hex("#39d98a"),
            accent2: hex("#5aa0e6"),
            good: hex("#78c878"),
            warn: hex("#dcc85a"),
            bad: hex("#dc6e5a"),
            grid: hex("#222c3a"),
            flow: [
                hex("#39d98a"), hex("#5aaae6"), hex("#e6aa50"),
                hex("#d26ec8"), hex("#78d2d2"), hex("#e6786e"),
            ],
        },
        Theme {
            name: "Aurora".into(),
            dark: true,
            bg: hex("#0f1420"),
            panel: hex("#18203a"),
            surface: hex("#0b1020"),
            text: hex("#e6ecf5"),
            muted: hex("#8893a8"),
            accent: hex("#7c5cff"),
            accent2: hex("#2ad5c8"),
            good: hex("#4fd6a0"),
            warn: hex("#ffcf5c"),
            bad: hex("#ff6b8b"),
            grid: hex("#232c46"),
            flow: [
                hex("#7c5cff"), hex("#2ad5c8"), hex("#ffcf5c"),
                hex("#ff6b8b"), hex("#5aa0e6"), hex("#a0e65a"),
            ],
        },
        Theme {
            name: "Nord".into(),
            dark: true,
            bg: hex("#2e3440"),
            panel: hex("#3b4252"),
            surface: hex("#272c36"),
            text: hex("#d8dee9"),
            muted: hex("#7b8694"),
            accent: hex("#88c0d0"),
            accent2: hex("#81a1c1"),
            good: hex("#a3be8c"),
            warn: hex("#ebcb8b"),
            bad: hex("#bf616a"),
            grid: hex("#434c5e"),
            flow: [
                hex("#88c0d0"), hex("#81a1c1"), hex("#a3be8c"),
                hex("#ebcb8b"), hex("#b48ead"), hex("#bf616a"),
            ],
        },
        Theme {
            name: "Solarized".into(),
            dark: true,
            bg: hex("#002b36"),
            panel: hex("#073642"),
            surface: hex("#00212b"),
            text: hex("#93a1a1"),
            muted: hex("#586e75"),
            accent: hex("#2aa198"),
            accent2: hex("#268bd2"),
            good: hex("#859900"),
            warn: hex("#b58900"),
            bad: hex("#dc322f"),
            grid: hex("#0a3a45"),
            flow: [
                hex("#2aa198"), hex("#268bd2"), hex("#859900"),
                hex("#b58900"), hex("#d33682"), hex("#cb4b16"),
            ],
        },
        Theme {
            name: "Paper".into(),
            dark: false,
            bg: hex("#f5f3ee"),
            panel: hex("#eae6dc"),
            surface: hex("#ffffff"),
            text: hex("#2b2a26"),
            muted: hex("#8a857a"),
            accent: hex("#2f8f6f"),
            accent2: hex("#2f6f9f"),
            good: hex("#2f8f4f"),
            warn: hex("#b08900"),
            bad: hex("#c0392b"),
            grid: hex("#ddd8cc"),
            flow: [
                hex("#2f8f6f"), hex("#2f6f9f"), hex("#b08900"),
                hex("#a0408f"), hex("#2f9f9f"), hex("#c0392b"),
            ],
        },
        Theme {
            name: "Mono".into(),
            dark: true,
            bg: hex("#0a0a0a"),
            panel: hex("#161616"),
            surface: hex("#000000"),
            text: hex("#e8e8e8"),
            muted: hex("#888888"),
            accent: hex("#f0f0f0"),
            accent2: hex("#bbbbbb"),
            good: hex("#9fd99f"),
            warn: hex("#d9cf9f"),
            bad: hex("#d99f9f"),
            grid: hex("#2a2a2a"),
            flow: [
                hex("#e8e8e8"), hex("#7fb0ff"), hex("#ffd27f"),
                hex("#ff9f9f"), hex("#9fffcf"), hex("#cf9fff"),
            ],
        },
    ]
}

/// Serde shape of a user theme file (`*.toml`).
#[derive(Deserialize)]
struct ThemeFile {
    name: String,
    #[serde(default = "default_true")]
    dark: bool,
    bg: String,
    panel: String,
    surface: String,
    text: String,
    muted: String,
    accent: String,
    accent2: String,
    good: String,
    warn: String,
    bad: String,
    grid: String,
    flow: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl ThemeFile {
    fn into_theme(self) -> Theme {
        let mut flow = [Color32::GRAY; 6];
        for (i, c) in self.flow.iter().take(6).enumerate() {
            flow[i] = hex(c);
        }
        Theme {
            name: self.name,
            dark: self.dark,
            bg: hex(&self.bg),
            panel: hex(&self.panel),
            surface: hex(&self.surface),
            text: hex(&self.text),
            muted: hex(&self.muted),
            accent: hex(&self.accent),
            accent2: hex(&self.accent2),
            good: hex(&self.good),
            warn: hex(&self.warn),
            bad: hex(&self.bad),
            grid: hex(&self.grid),
            flow,
        }
    }
}

/// The `…/hopscout/themes` directory, creating it (with a starter template) the
/// first time so users have somewhere obvious to drop their own palettes.
pub fn themes_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "hopscout")?;
    let dir = dirs.config_dir().join("themes");
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("custom-example.toml"), STARTER_TOML);
    }
    Some(dir)
}

/// Load every valid `*.toml` palette from the themes directory.
pub fn load_custom() -> Vec<Theme> {
    let Some(dir) = themes_dir() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(tf) = toml::from_str::<ThemeFile>(&text) {
                out.push(tf.into_theme());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parses() {
        assert_eq!(hex("#ff8000"), Color32::from_rgb(255, 128, 0));
        assert_eq!(hex("39d98a"), Color32::from_rgb(0x39, 0xd9, 0x8a));
    }

    #[test]
    fn starter_toml_is_valid() {
        let tf: ThemeFile = toml::from_str(STARTER_TOML).expect("starter parses");
        let t = tf.into_theme();
        assert_eq!(t.name, "Custom Example");
        assert_eq!(t.accent, hex("#ff7a59"));
        assert!(t.dark);
        assert_eq!(t.flow[1], hex("#59b6ff"));
    }

    #[test]
    fn all_includes_builtins() {
        // also exercises themes_dir() creation + custom loading
        assert!(all().len() >= 6);
    }
}

const STARTER_TOML: &str = r##"# hopscout custom theme — copy and tweak. Colors are #rrggbb (or #rrggbbaa).
name = "Custom Example"
dark = true
bg      = "#101418"
panel   = "#1b222b"
surface = "#0b0f14"
text    = "#d6dde6"
muted   = "#7c8794"
accent  = "#ff7a59"
accent2 = "#59b6ff"
good    = "#6fcf86"
warn    = "#e6c25a"
bad     = "#e0685a"
grid    = "#26303a"
flow    = ["#ff7a59", "#59b6ff", "#e6c25a", "#c06ed0", "#5ad2c2", "#e06e6e"]
"##;
