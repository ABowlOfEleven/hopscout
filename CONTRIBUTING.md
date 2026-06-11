# Contributing to hopscout

## Clean-room - important

`mtr` and `WinMTR` are **GPL-2.0**. hopscout is MIT and a clean reimplementation.
Do **not** copy, paste, or transcribe code from `mtr`, `WinMTR`, or any other
GPL/copyleft source into this project. Design from RFCs and observable protocol
behavior only. A single pasted function can impose copyleft obligations on the
whole codebase and destroy the license. If in doubt, ask before committing.

## Developer Certificate of Origin (DCO)

We use the DCO instead of a CLA. Every commit must be signed off, certifying you
wrote the code (or have the right to contribute it under MIT):

```pwsh
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line.

## Unsafe code

`unsafe` is **forbidden** in every crate except `hopscout-net`, which is the one
sanctioned Win32 FFI boundary. New `unsafe` belongs there, behind a safe API,
with a `// SAFETY:` comment on each block. Do not reach for `unsafe` elsewhere.

## Network input is untrusted

Anything parsed off the wire (ICMP/TCP/UDP responses) is attacker-influenced.
Bounds-check, prefer `read_unaligned` over transmute, and keep parsers panic-free.
