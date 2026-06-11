# hopscout

A modern traceroute + continuous-monitoring tool for Windows — native, no
elevation required for the default path — with a `ratatui` CLI and an `egui`
GUI sharing one engine. MTR parity, plus ASN/Geo enrichment, path-change
alerting, multi-target dashboards, and multipath (Paris) discovery.

> Status: **Phases 1–2 working.** Concurrent rung-1 engine (unprivileged ICMP,
> IPv4 **and IPv6**), live `ratatui` CLI, `egui` GUI, rDNS + ASN enrichment, and
> rung-2 **UDP traceroute** via raw sockets with capability detection +
> self-elevation. Branding (icon, version metadata, About) is in. Rung 3 (Npcap)
> and Paris multipath are next.

## Workspace

| Crate | Role | Unsafe | State |
|-------|------|--------|-------|
| `hopscout-core`   | Probe engine, `Session` model, rolling stats, the `ProbeBackend` trait. | forbidden | working |
| `hopscout-net`    | The single Win32 FFI boundary. Rung-1 ICMP today; raw sockets + Npcap later. | allowed (FFI) | working |
| `hopscout-enrich` | Background reverse-DNS + origin-ASN (Team Cymru WHOIS) enrichment. | forbidden | working |
| `hopscout-cli`    | `ratatui` live trace table. | forbidden | working |
| `hopscout-gui`    | `egui` app — live table + per-hop sparklines. | forbidden | working |

## Capability ladder

| Capability | Backend | Privilege |
|------------|---------|-----------|
| ICMP trace + ping (IPv4) | `IcmpSendEcho2` | none |
| rDNS / ASN / GeoIP / map / alerts / multi-target | userspace | none |
| Sub-floor intervals, jumbo payloads, UDP/TCP modes, Paris multipath | raw socket / Npcap | admin (via an elevated probe helper) |

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
| `-p, --proto <p>`     | `icmp` or `udp` (udp needs admin) | icmp |
| `-V, --version`       | print version                | — |

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

Enter a host, press Start, and watch the live table (loss/RTT/jitter, with
reverse-DNS and ASN filling in). Click a hop to see its recent-RTT sparkline;
Pause/Resume/Reset from the top bar.

### Headless smoke trace

```pwsh
cargo run -p hopscout-net --example trace -- 8.8.8.8 10
```

Starts the engine for ~10s and prints a snapshot (host, ASN, loss, RTT) — handy
on machines without a TTY.

## License

MIT — see [LICENSE](LICENSE). Contributions are clean-room (no GPL `mtr` /
`WinMTR` code); see [CONTRIBUTING.md](CONTRIBUTING.md).
