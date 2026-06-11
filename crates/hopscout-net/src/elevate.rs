//! Self-elevation: relaunch the current executable with the `runas` verb so the
//! user gets a UAC prompt, then the elevated copy can open the raw socket.
//!
//! This is the simple privilege path for rung 2. A future hardening is full
//! privilege *separation* - a tiny always-elevated helper that owns only the
//! socket and talks to the unprivileged UI over a named pipe - so the large
//! surface never runs as admin. The capability/IPC seam is shaped for that.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;
use windows::core::PCWSTR;

/// Relaunch this process elevated with the same arguments. On success the
/// elevated copy is starting in a new console; the caller should exit.
pub fn relaunch_elevated() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let params = std::env::args()
        .skip(1)
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(" ");
    runas(&exe.to_string_lossy(), &params)
}

/// Launch the privilege-separation helper (`hopscout-helper.exe`, expected next
/// to this executable) elevated. It hosts the raw socket / Npcap and serves the
/// unprivileged app over a named pipe, so the main process need not be admin.
pub fn spawn_helper_elevated() -> io::Result<()> {
    let dir = std::env::current_exe()?
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    let helper = dir.join("hopscout-helper.exe");
    runas(&helper.to_string_lossy(), "")
}

/// Run `exe` with the `runas` verb (triggers UAC). Returns Ok if ShellExecuteW
/// reports success (> 32).
fn runas(exe: &str, params: &str) -> io::Result<()> {
    let verb = wide("runas");
    let file = wide(exe);
    let parameters = wide(params);

    // SAFETY: all PCWSTRs point to NUL-terminated wide buffers that outlive the
    // call. ShellExecuteW returns an HINSTANCE-shaped status; > 32 means success.
    let status = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(parameters.as_ptr()),
            PCWSTR::null(),
            SW_NORMAL,
        )
    };
    if status.0 as usize > 32 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
