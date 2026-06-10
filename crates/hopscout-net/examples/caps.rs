//! Print detected capabilities. Run unprivileged vs. elevated to see the gate.
//!
//!   cargo run -p hopscout-net --example caps

fn main() {
    let caps = hopscout_net::detect_caps();
    println!("hopscout capabilities:");
    println!("  elevated (admin token): {}", caps.elevated);
    println!("  raw ICMP socket:        {}", caps.raw_icmp);
    println!(
        "  rung-2 UDP/TCP modes:   {}",
        if caps.rung2() { "available" } else { "needs elevation" }
    );
}
