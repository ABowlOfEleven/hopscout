# hopscout

A modern traceroute + continuous-monitoring tool for Windows — native, no
elevation required for the default path — with a `ratatui` CLI and an `egui`
GUI sharing one engine. MTR parity, plus ASN/Geo enrichment, path-change
alerting, multi-target dashboards, and multipath (Paris) discovery.

> Status: **Phases 1–3 working.** All three protocols run: rung-1 **ICMP**
> (unprivileged, IPv4 + IPv6), rung-2 **UDP** (raw `SIO_RCVALL` sniffer, admin),
> and rung-3 **TCP-SYN** via Npcap (runtime-loaded, never bundled) with ACK/IP-id
> correlation. Live `ratatui` CLI, `egui` GUI, rDNS + ASN enrichment, capability
> detection + self-elevation, and full branding (icon, version metadata, About).
> Paris multipath visualization and the elevated-helper privilege *separation*
> are the next refinements.

## Workspace

| Crate | Role | Unsafe | State |
|-------|------|--------|-------|
| `hopscout-core`   | Probe engine, `Session` model, rolling stats, the `ProbeBackend` trait. | forbidden | working |
| `hopscout-net`    | The single Win32 FFI boundary. Rung 1 (ICMP), rung 2 (raw UDP), rung 3 (Npcap TCP-SYN), capability detection, self-elevation. | allowed (FFI) | working |
| `hopscout-enrich` | Background reverse-DNS, origin-ASN (Cymru WHOIS), and geolocation (ip-api). | forbidden | working |
| `hopscout-cli`    | `ratatui` live trace table. | forbidden | working |
| `hopscout-gui`    | `egui` app — live table + per-hop sparklines. | forbidden | working |

## Capability ladder

| Capability | Backend | Privilege | Status |
|------------|---------|-----------|--------|
| ICMP trace + ping (IPv4 + IPv6) | `Icmp[6]SendEcho2` | none | ✅ |
| rDNS / ASN enrichment | userspace (Cymru WHOIS) | none | ✅ |
| UDP traceroute | raw `SIO_RCVALL` sniffer | admin | ✅ |
| TCP-SYN traceroute (trace to `:443`) | Npcap injection | Npcap + admin | ✅ |
| Paris multipath, GeoIP map, path-change alerts | Npcap / userspace | varies | planned |

Npcap (rung 3) is **runtime-loaded** via `libloading`, never bundled — its
license restricts redistribution. hopscout builds and runs without the Npcap
SDK; TCP mode lights up only when Npcap is installed ([npcap.com](https://npcap.com)).

## Architecture notes

- **One persistent thread per hop.** Each worker owns its own ICMP handle and
  loops independently, so a timing-out router stalls only its own row. Path
  length converges on its own: once any hop sees the destination reply, a shared
  `path_len` shrinks to the smallest such TTL and deeper hops idle.
- **Enrichment is async and cached.** A background thread fills hostnames and AS
  numbers as hops appear, with all DNS/WHOIS I/O performed off the session lock.
  ASNs are batched into one WHOIS query and written immediately; reverse DNS
  trickles in behind them.
- **Honest stats.** Loss, plus O(1) Welford rolling mean and jitter (RTT
  stddev). Streaming percentiles are planned.

## CLI usage

```pwsh
cargo run -p hopscout-cli -- 8.8.8.8
cargo run -p hopscout-cli -- one.one.one.one -i 500 -m 40
```

| Flag | Meaning | Default |
|------|---------|---------|
| `-i, --interval <ms>` | delay between probes per hop | 1000 |
| `-w, --timeout <ms>`  | per-probe timeout            | 1000 |
| `-m, --max-hops <n>`  | maximum TTL to probe         | 30 |
| `-s, --size <n>`      | payload bytes                | 32 |
| `-4` / `-6`           | force IPv4 / IPv6            | auto |
| `-p, --proto <p>`     | `icmp` \| `udp` \| `tcp`     | icmp |
| `-P, --port <n>`      | destination port (tcp mode) | 443 |
| `-V, --version`       | print version                | — |

`udp` needs admin (raw sniffer); `tcp` needs Npcap + admin (packet injection).
hopscout detects the gap and relaunches itself elevated.

Keys: `q`/`Esc` quit · `p`/space pause · `r` reset.

UDP mode (`-p udp`) opens a raw `SIO_RCVALL` sniffer to capture ICMP errors,
which requires elevation — hopscout detects this and relaunches itself with a
UAC prompt. The brand identity (name/version/icon) lives in
[`assets/`](assets/) and `crates/hopscout-core/src/brand.rs`, embedded into both
`.exe`s via `winresource`.

## GUI usage

```pwsh
cargo run -p hopscout-gui            # enter a target in the window
cargo run -p hopscout-gui -- 8.8.8.8 # auto-start a target
```

Pick a protocol (ICMP/UDP/TCP) and port, enter a host, press Start. Three views:

- **Table** — live loss/RTT/jitter with rDNS + ASN; click a hop for its sparkline.
- **Map** — hops plotted by geolocation on an equirectangular grid, path arcs + city labels.
- **Topology** — TTL columns of hop addresses with ASN coloring; multiple nodes in a column reveal ECMP/multipath.

Pause/Resume/Reset from the top bar; UDP/TCP prompt to relaunch elevated when needed.

### Headless smoke trace

```pwsh
cargo run -p hopscout-net --example trace -- 8.8.8.8 10
```

Starts the engine for ~10s and prints a snapshot (host, ASN, loss, RTT) — handy
on machines without a TTY.

## License

MIT — see [LICENSE](LICENSE). Contributions are clean-room (no GPL `mtr` /
`WinMTR` code); see [CONTRIBUTING.md](CONTRIBUTING.md).
