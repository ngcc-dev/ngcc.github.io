<!-- synchronized report: hash-11/report.md -->
Candidate: Garnet
Family: Symmetric (AES-derived hash)
Archive: [Garnet.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Garnet.zip) (SHA-256: `9cb659f7e01a64bdcce2a4fea8a7d6e6b5687b2a0ed8ce4ffe5fa86dd3e77646`)

## hash-11-1: Secret state indexes AES T-tables

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference Garnet variants
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Each AES-like round indexes four 1-KiB T-tables with bytes of the evolving hash state (`Garnet_1024.c:278-281`; `Garnet_512.c:322-325`). These indices depend on the message and select different cache lines, exposing state-dependent memory addresses in a shared-cache setting. A two-entry reduction table is also indexed by a state bit. No preimage-recovery exploit is claimed. See [constant_time.md](../constant-time/hash-11.md).

### Reproducing

Inspect the cited `TE0`–`TE3` loads; identical-length inputs with different first blocks produce different state-derived table indices. This is an address-trace witness, not a timing-extraction benchmark.
