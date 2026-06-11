//! hopscout-helper - the elevated half of hopscout's privilege separation.
//!
//! Run this elevated (the app launches it via UAC). It owns the raw socket /
//! Npcap and serves the unprivileged app over a named pipe; it parses nothing
//! attacker-controlled beyond fixed-size probe frames. The app stays at medium
//! integrity.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    {
        eprintln!("hopscout-helper: serving on {}", hopscout_net::PIPE_NAME);
        if let Err(e) = hopscout_net::serve_helper() {
            eprintln!("hopscout-helper: {e}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    eprintln!("hopscout-helper is Windows-only");
}
