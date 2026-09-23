<!-- synchronized report: hash-27/report.md -->
Candidate: Vedak
Family: Symmetric (sponge hash)
Archive: [Vedak.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Vedak.zip)

## hash-27-1: Secret state indexes an eight-bit substitution table

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference Vedak-512/768/1024
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Every `apply_S` call reads the 256-byte `S_BOX_8` at eight indices from each evolving state word (`CryptHash_AlgorithmInstance.c:167-180` in Vedak-512, `:165-178` in Vedak-768/1024); the table is declared at `:57` in Vedak-512. These accesses select cache lines according to secret message-dependent state. The separate source-level `if (bit)` in message copying is *not* part of this finding: GCC `-O2` makes it branchless. No preimage-recovery exploit is claimed. See [constant_time.md](../constant-time/hash-27.md).

### Reproducing

Inspect `apply_S` in any reference variant and its call from `vedak_p40` (`CryptHash_AlgorithmInstance.c:243` in Vedak-512, `:241` in Vedak-768/1024); the S-box index is computed from state bytes rather than a public loop index.
