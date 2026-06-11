//! Shared product identity — one source of truth for the app's name, version,
//! and strings used by the CLI, GUI, installer metadata, and `.exe` resources.

/// Lowercase program / command name.
pub const NAME: &str = "hopscout";
/// Display name for window titles and About boxes.
pub const DISPLAY_NAME: &str = "hopscout";
/// Crate version (workspace-wide).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Short tagline.
pub const TAGLINE: &str = "a better traceroute for Windows";
/// One-line description (file metadata, --help banners).
pub const DESCRIPTION: &str =
    "Live traceroute & network monitor — ICMP/UDP, IPv4/IPv6, ASN + rDNS enrichment";
/// Project home.
pub const REPOSITORY: &str = "https://github.com/ABowlOfEleven/hopscout";
/// Copyright / authors line.
pub const AUTHORS: &str = "hopscout contributors";

/// `"hopscout 0.1.0"` — name + version for titles and banners.
pub fn name_version() -> String {
    format!("{DISPLAY_NAME} {VERSION}")
}
