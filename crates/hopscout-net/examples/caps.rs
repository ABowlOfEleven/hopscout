//! Print detected capabilities. Run unprivileged vs. elevated to see the gate.
//!
//!   cargo run -p hopscout-net --example caps

fn main() {
    let caps = hopscout_net::detect_caps();
    println!("hopscout capabilities:");
    println!("  elevated (admin token): {}", caps.elevated);
    println!("  raw sniffer (RCVALL):   {}", caps.raw_icmp);
    println!("  npcap installed:        {}", caps.npcap);
    println!(
        "  rung-2 UDP mode:        {}",
        if caps.rung2() { "available" } else { "needs elevation" }
    );
    println!(
        "  rung-3 TCP/Paris mode:  {}",
        if caps.rung3() { "available" } else { "needs Npcap (npcap.com)" }
    );

    if let Ok(np) = hopscout_net::Npcap::load() {
        if let Ok(devs) = np.list_devices() {
            println!("  npcap devices:          {}", devs.len());
        }
    }
}
