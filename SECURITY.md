# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[security advisories](https://github.com/ABowlOfEleven/hopscout/security/advisories/new)
rather than opening a public issue. I'll respond as soon as I can.

## Scope notes

A few things worth knowing about how hopscout is built:

- `unsafe` is confined to the `hopscout-net` crate, which is the single Win32 FFI
  boundary; every other crate is `#![forbid(unsafe_code)]`.
- Default ICMP traceroute needs no elevation. UDP and TCP modes need administrator
  rights (raw socket / Npcap). The probe helper (`hopscout-helper`) is the only
  component meant to run elevated; the named-pipe interface between it and the
  app is a hardening work in progress, so treat that path as experimental.
- Network responses are attacker-influenced. Parsers (ICMP, TCP, ICMP extensions)
  are bounds-checked and panic-free; if you find a parser that can be made to
  panic or misbehave on crafted input, that's in scope.
- Npcap is never bundled; it is loaded at runtime only if already installed.

## Supported versions

The latest release is supported. This is an early project, so please test against
`main` before reporting.
