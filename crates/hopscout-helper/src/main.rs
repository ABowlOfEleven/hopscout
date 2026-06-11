//! hopscout-helper - the elevated half of hopscout's privilege separation.
//!
//! Run this elevated (the app launches it via UAC). It owns the raw socket /
//! Npcap and serves the unprivileged app over a named pipe; it parses nothing
//! attacker-controlled beyond fixed-size probe frames. The app stays at medium
//! integrity.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Serving blocks forever on the named pipe, so only do it when explicitly
    // asked (the app launches us elevated with `--serve`). A bare invocation
    // just prints what we are and exits, so running the exe directly never
    // hangs - which also keeps automated installer validators from blocking on
    // a process that intentionally runs until killed.
    let serve = std::env::args().skip(1).any(|a| a == "--serve");
    if !serve {
        println!(
            "hopscout-helper is the elevated probe helper for hopscout. The app \
             launches it automatically with --serve; running it directly does \
             nothing."
        );
        return;
    }

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
