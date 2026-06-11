# hopscout

A modern traceroute + continuous-monitoring tool for Windows — native, no
elevation required for the default path — with a `ratatui` CLI and an `egui`
GUI sharing one engine. MTR parity, plus ASN/Geo enrichment, path-change
alerting, multi-target dashboards, and multipath (Paris) discovery.

> Status: **Feature-complete core.** All three protocols (rung-1 **ICMP**
> unprivileged IPv4+IPv6, rung-2 **UDP** via raw `SIO_RCVALL`, rung-3 **TCP-SYN**
> via runtime-loaded Npcap), **active multipath** (per-flow ECMP discovery),
> **path-change alerting**, a **multi-target dashboard**, and GeoIP map +
> topology DAG views. Live `ratatui` CLI and `egui` GUI over one engine, with
> rDNS/ASN/geo enrichment, capability detection + self-elevation, and full
> branding. The privilege-*separation* helper (vs current self-elevation) and
> map coastlines remain as polish.

## Workspace

| Crate | Role | Unsafe | State |
|-------|------|--------|-------|
| `hopscout-core`   | Probe engine, `Session` model, rolling stats, the `ProbeBackend` trait. | forbidden | working |
| `hopscout-net`    | The single Win32 FFI boundary. Rung 1 (ICMP), rung 2 (raw UDP), rung 3 (Npcap TCP-SYN), capability detection, self-elevation. | allowed (FFI) | working |
| `hopscout-enrich` | Background reverse-DNS, origin-ASN (Cymru WHOIS), and geolocation (ip-api). | forbidden | working |
| `hopscout-cli`    | `ratatui` live trace table. | forbidden | working |
| `hopscout-gui`    | `egui` app — table/map/topology/alerts, themes, multi-target. | forbidden | working |
| `hopscout-helper` | Elevated probe helper (privilege separation) over a named pipe. | forbidden | builds; needs admin to run |

## Capability ladder

| Capability | Backend | Privilege | Status |
|------------|---------|-----------|--------|
| ICMP trace + ping (IPv4 + IPv6) | `Icmp[6]SendEcho2` | none | ✅ |
| rDNS / ASN enrichment | userspace (Cymru WHOIS) | none | ✅ |
| UDP traceroute | raw `SIO_RCVALL` sniffer | admin | ✅ |
| TCP-SYN traceroute (trace to `:443`) | Npcap injection | Npcap + admin | ✅ |
| Active multipath (per-flow ECMP) | UDP/TCP flow tuples | per protocol | ✅ |
| GeoIP map · topology DAG · path-change alerts · multi-target | userspace | none | ✅ |

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
| `-f, --flows <n>`     | concurrent flows (multipath) | 1 |
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
- **Topology** — TTL columns of hop addresses with ASN coloring; with `flows > 1` each flow draws its own polyline, so ECMP fan-out and reconvergence are visible.
- **Alerts** — capture a baseline, then watch live deviations (route change, hop appear/disappear, latency regression, loss onset).

Add several targets to monitor them side by side (left panel). Set `flows` for
multipath. Pause/Resume/Reset and UDP/TCP elevation prompts from the top bar.

### Themes

Six built-in themes (Midnight, Aurora, Nord, Solarized, Paper, Mono) selectable
from the top bar. Drop your own `*.toml` palette into
`%APPDATA%\hopscout\config\themes\` (a `custom-example.toml` is written there on
first run) and hit **⟳** to load it. Each theme recolors the whole UI including
the map, topology, and table.

### Privilege separation (in progress)

`hopscout-helper.exe` is the elevated half: it owns the raw socket / Npcap and
serves the unprivileged app over a named pipe, so the main process never runs as
admin. The message framing and server are in place; the cross-elevation pipe ACL
and app wiring (vs. the current whole-app self-elevation) are the finishing
steps.

### Headless smoke trace

```pwsh
cargo run -p hopscout-net --example trace -- 8.8.8.8 10
```

Starts the engine for ~10s and prints a snapshot (host, ASN, loss, RTT) — handy
on machines without a TTY.

## License

MIT — see [LICENSE](LICENSE). Contributions are clean-room (no GPL `mtr` /
`WinMTR` code); see [CONTRIBUTING.md](CONTRIBUTING.md).
