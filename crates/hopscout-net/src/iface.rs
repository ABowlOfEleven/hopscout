//! Layer-2 path facts the Npcap injector needs: which capture device, our MAC,
//! and the next-hop (gateway) MAC for a destination.

use core::ffi::c_void;
use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersInfo, GetBestRoute, IP_ADAPTER_INFO, MIB_IPFORWARDROW, SendARP,
};

/// Everything needed to frame and inject a packet toward a destination.
pub struct L2Path {
    /// Npcap device name, e.g. `\Device\NPF_{GUID}`.
    pub device: String,
    pub src_mac: [u8; 6],
    /// Next-hop (gateway, or destination if on-link) MAC.
    pub gw_mac: [u8; 6],
}

fn ip_u32(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// Resolve the device + MACs to reach `dest` from `src_ip`.
pub fn resolve(dest: Ipv4Addr, src_ip: Ipv4Addr) -> io::Result<L2Path> {
    let (device, src_mac) = adapter_for(src_ip)?;
    let nexthop = next_hop(dest)?;
    let gw_mac = arp(nexthop, src_ip)?;
    Ok(L2Path {
        device,
        src_mac,
        gw_mac,
    })
}

/// The next-hop IP toward `dest` (the gateway, or `dest` itself if on-link).
fn next_hop(dest: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let mut row = MIB_IPFORWARDROW::default();
    // SAFETY: row is a valid out-param for GetBestRoute.
    let rc = unsafe { GetBestRoute(ip_u32(dest), None, &mut row) };
    if rc != 0 {
        return Err(io::Error::other("GetBestRoute failed"));
    }
    let nh = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
    Ok(if nh.is_unspecified() { dest } else { nh })
}

/// Resolve `target`'s MAC via ARP (sourced from `src`).
fn arp(target: Ipv4Addr, src: Ipv4Addr) -> io::Result<[u8; 6]> {
    let mut mac = [0u8; 8];
    let mut len: u32 = mac.len() as u32;
    // SAFETY: mac/len are valid out-params; SendARP fills up to len bytes.
    let rc = unsafe {
        SendARP(
            ip_u32(target),
            ip_u32(src),
            mac.as_mut_ptr() as *mut c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::other("SendARP failed (next-hop MAC)"));
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&mac[..6]);
    Ok(out)
}

/// Find the adapter that owns `src_ip`; return its Npcap device name + MAC.
fn adapter_for(src_ip: Ipv4Addr) -> io::Result<(String, [u8; 6])> {
    let mut size: u32 = 0;
    // SAFETY: sizing call — returns ERROR_BUFFER_OVERFLOW and sets `size`.
    unsafe {
        let _ = GetAdaptersInfo(None, &mut size);
    }
    if size == 0 {
        return Err(io::Error::other("GetAdaptersInfo returned size 0"));
    }
    let mut buf = vec![0u8; size as usize];
    let head = buf.as_mut_ptr() as *mut IP_ADAPTER_INFO;
    // SAFETY: buf is sized per the first call.
    let rc = unsafe { GetAdaptersInfo(Some(head), &mut size) };
    if rc != 0 {
        return Err(io::Error::other("GetAdaptersInfo failed"));
    }

    let mut cur: *const IP_ADAPTER_INFO = head;
    while !cur.is_null() {
        // SAFETY: cur is a live node in the adapter list.
        let info = unsafe { &*cur };

        let mut node: *const _ = &info.IpAddressList;
        while !node.is_null() {
            // SAFETY: node is a live IP_ADDR_STRING.
            let s = unsafe { &*node };
            let ip = unsafe { CStr::from_ptr(s.IpAddress.String.as_ptr() as *const c_char) }
                .to_string_lossy();
            if ip.parse::<Ipv4Addr>() == Ok(src_ip) {
                let name = unsafe { CStr::from_ptr(info.AdapterName.as_ptr() as *const c_char) }
                    .to_string_lossy()
                    .into_owned();
                let n = (info.AddressLength as usize).min(6);
                let mut mac = [0u8; 6];
                mac[..n].copy_from_slice(&info.Address[..n]);
                return Ok((format!(r"\Device\NPF_{name}"), mac));
            }
            node = unsafe { (*node).Next };
        }
        cur = info.Next;
    }
    Err(io::Error::other("no adapter matched the source IP"))
}

use core::ffi::c_char;
