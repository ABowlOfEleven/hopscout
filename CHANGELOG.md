# Changelog

All notable changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

## [0.1.1]

CLI and GUI feature parity.

- Shared rendering: the text / JSON / CSV report generators and the MTR-style
  stat columns moved into `hopscout-core`, so the CLI and GUI render the same
  way from the same code.
- GUI gained the engine controls the CLI already exposed: IPv4 / IPv6 family,
  payload size, per-probe timeout, first TTL, and a no-DNS toggle, plus a
  show-IPs toggle, a Location (city / country) column, inline MPLS labels, and
  an Export menu that saves text / JSON / CSV reports.
- CLI gained a Location column and a dedicated alerts view (toggle `a`); the
  `-b` / show-IPs flag is now wired into the live table.
- Reports now carry geolocation: CSV gains City / Country columns and JSON adds
  asn / city / country per hop.

## [0.1.0]

First release.

- Concurrent rung-1 ICMP traceroute engine (unprivileged, IPv4 + IPv6) on
  `Icmp[6]SendEcho2`, with O(1) rolling stats and streaming p50/p95/p99.
- Rung-2 UDP traceroute via a raw `SIO_RCVALL` sniffer (admin), and rung-3
  TCP-SYN via runtime-loaded Npcap, with capability detection and self-elevation.
- Active multipath (per-flow ECMP) discovery and path MTU discovery.
- Background reverse-DNS, origin-ASN (Team Cymru), and geolocation (ip-api)
  enrichment.
- MTR-compatible CLI: live view plus report / JSON / CSV, first-ttl, MPLS (`-z`),
  field ordering (`-o`), and the usual MTR flags.
- egui GUI: table, world map (coastlines, zoom/pan), topology DAG, alerts,
  multi-target dashboard, six built-in themes plus custom TOML themes.
- Path-change alerting against a captured baseline.
- Privilege-separation helper (`hopscout-helper`) over a named pipe (in progress).
- Windows installer (WiX v5 MSI) and portable zip.
