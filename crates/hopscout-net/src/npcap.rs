//! Runtime loading of Npcap's `wpcap.dll`.
//!
//! Npcap is **not bundled** - its license restricts redistribution (see
//! CONTRIBUTING). We load it dynamically with `libloading`, so hopscout builds
//! and runs without the Npcap SDK; rung-3 features simply light up when the user
//! has Npcap installed. This module wraps just the handful of `pcap_*` functions
//! the TCP-SYN backend needs.

use core::ffi::{c_char, c_int, c_long, c_void};
use std::ffi::{CStr, CString};
use std::io;
use std::sync::Arc;

use libloading::{Library, Symbol};

const PCAP_ERRBUF_SIZE: usize = 256;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *const c_char,
    description: *const c_char,
    addresses: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct PcapPkthdr {
    ts_sec: c_long,
    ts_usec: c_long,
    caplen: u32,
    len: u32,
}

type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type OpenLive =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type Sendpacket = unsafe extern "C" fn(*mut c_void, *const u8, c_int) -> c_int;
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
type CloseFn = unsafe extern "C" fn(*mut c_void);

/// A loaded `wpcap.dll`.
pub struct Npcap {
    lib: Library,
}

impl Npcap {
    /// Load Npcap, searching the loader path and the standard install dir.
    pub fn load() -> io::Result<Self> {
        let candidates = ["wpcap.dll", r"C:\Windows\System32\Npcap\wpcap.dll"];
        let mut last: Option<libloading::Error> = None;
        for c in candidates {
            // SAFETY: loading a system DLL by name; no init routine is invoked
            // by us beyond the loader's own.
            match unsafe { Library::new(c) } {
                Ok(lib) => return Ok(Self { lib }),
                Err(e) => last = Some(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Npcap wpcap.dll not found ({last:?}); install from https://npcap.com"),
        ))
    }

    /// True if Npcap is installed and loadable.
    pub fn available() -> bool {
        Self::load().is_ok()
    }

    fn sym<'a, T>(&'a self, name: &[u8]) -> io::Result<Symbol<'a, T>> {
        // SAFETY: each symbol's type matches the documented pcap signature.
        unsafe { self.lib.get::<T>(name) }.map_err(|e| {
            io::Error::other(format!("wpcap symbol {}: {e}", String::from_utf8_lossy(name)))
        })
    }

    /// Enumerate capture device names (e.g. `\Device\NPF_{GUID}`).
    pub fn list_devices(&self) -> io::Result<Vec<String>> {
        let find: Symbol<FindAllDevs> = self.sym(b"pcap_findalldevs\0")?;
        let free: Symbol<FreeAllDevs> = self.sym(b"pcap_freealldevs\0")?;

        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let mut head: *mut PcapIf = core::ptr::null_mut();
        // SAFETY: head/errbuf are valid out-params for the call.
        let rc = unsafe { find(&mut head, errbuf.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::other("pcap_findalldevs failed"));
        }

        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: cur is a live node; name is a valid C string.
            let name = unsafe { CStr::from_ptr((*cur).name) }
                .to_string_lossy()
                .into_owned();
            out.push(name);
            cur = unsafe { (*cur).next };
        }
        // SAFETY: head came from pcap_findalldevs and is freed once.
        unsafe { free(head) };
        Ok(out)
    }
}

/// An open live capture/inject handle on one device. Owns an `Arc<Npcap>` so it
/// can be moved to a worker thread (one capture per hop).
pub struct Capture {
    npcap: Arc<Npcap>,
    handle: *mut c_void,
}

// SAFETY: each worker thread owns its own Capture; the pcap handle is only ever
// used from that thread.
unsafe impl Send for Capture {}

impl Capture {
    /// Open `device` for layer-2 send + capture (promiscuous, 10 ms read timeout).
    pub fn open(npcap: Arc<Npcap>, device: &str) -> io::Result<Self> {
        let open: Symbol<OpenLive> = npcap.sym(b"pcap_open_live\0")?;
        let cname = CString::new(device).map_err(|_| io::Error::other("bad device name"))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        // SAFETY: cname/errbuf are valid; returns null on failure.
        let handle = unsafe { open(cname.as_ptr(), 65536, 1, 10, errbuf.as_mut_ptr()) };
        if handle.is_null() {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(io::Error::other(format!("pcap_open_live: {msg}")));
        }
        Ok(Self { npcap, handle })
    }

    /// Inject a fully-framed Ethernet packet.
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        let send: Symbol<Sendpacket> = self.npcap.sym(b"pcap_sendpacket\0")?;
        // SAFETY: handle is live; frame is a valid byte slice.
        let rc = unsafe { send(self.handle, frame.as_ptr(), frame.len() as c_int) };
        if rc != 0 {
            return Err(io::Error::other("pcap_sendpacket failed"));
        }
        Ok(())
    }

    /// Poll for the next captured frame. `Ok(None)` means the read timed out.
    pub fn next_frame(&self) -> io::Result<Option<Vec<u8>>> {
        let next: Symbol<NextEx> = self.npcap.sym(b"pcap_next_ex\0")?;
        let mut hdr: *mut PcapPkthdr = core::ptr::null_mut();
        let mut data: *const u8 = core::ptr::null();
        // SAFETY: out-params are valid; data/hdr are owned by the capture.
        let rc = unsafe { next(self.handle, &mut hdr, &mut data) };
        match rc {
            1 => {
                let len = unsafe { (*hdr).caplen } as usize;
                let bytes = unsafe { core::slice::from_raw_parts(data, len) }.to_vec();
                Ok(Some(bytes))
            }
            0 => Ok(None), // timeout
            _ => Err(io::Error::other("pcap_next_ex error")),
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Ok(close) = self.npcap.sym::<CloseFn>(b"pcap_close\0") {
            // SAFETY: handle came from pcap_open_live and is closed once.
            unsafe { close(self.handle) };
        }
    }
}
