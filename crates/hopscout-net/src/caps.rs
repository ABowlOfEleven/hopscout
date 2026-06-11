//! Capability detection: process elevation and raw-socket availability.

use core::ffi::c_void;
use core::mem::size_of;

use hopscout_core::Capabilities;

/// Probe what this process can do right now.
pub fn detect() -> Capabilities {
    Capabilities {
        elevated: is_elevated(),
        raw_icmp: raw_sniffer_available(),
        npcap: crate::npcap::Npcap::available(),
    }
}

/// True if the process token is elevated (running as admin).
fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: standard token query. We open our own process token, read the
    // fixed-size TOKEN_ELEVATION, and close the handle.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// True if we can actually stand up the rung-2 sniffer (raw IP + `SIO_RCVALL`),
/// which is what UDP/TCP modes need to receive ICMP errors. This needs admin -
/// note that a plain raw ICMP socket may open without it but can't see errors.
fn raw_sniffer_available() -> bool {
    use std::net::Ipv4Addr;
    match crate::raw::local_ipv4_for(Ipv4Addr::new(8, 8, 8, 8)) {
        Ok(local) if !local.is_unspecified() => crate::raw::can_sniff(local),
        _ => false,
    }
}
