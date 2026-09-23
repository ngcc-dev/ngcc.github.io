<!-- synchronized report: kem-04/report.md -->
Candidate: BAG-Piglet
Family: Code-based (rank metric)
Archive: [BAG-Piglet.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BAG-Piglet.zip) (SHA-256: `31afe1f2f4e97ad77929d7855c7d9011d69755049d155c09be9339bc99b1d405`)

## kem-04-1: Secret-dependent pivoting in the Gabidulin decoder

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all four parameter sets
Discovery: Moderate
Exploitation: Local control-flow/cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The decapsulator expands the private PKE key and decrypts a chosen ciphertext. The resulting word combines ciphertext with private `x` (`src/scheme/bag_piglet.c:325-378`). The augmented-Gabidulin decoder calls `gabidulin_code_decode_3`; its discrepancy-dependent loop chooses a pivot index and branches on discrepancy values (`src/common/gabidulin.c:273-390`). The branchless final KEM fallback selection does not hide that earlier secret-dependent control flow and memory access. No inversion from observed pivots to private `x` has been shown, so this is not rated a full key-recovery or remote attack.

### Reproducing

The source-level witness is the chain `src/common/ccakem.c:125-132` → `src/scheme/bag_piglet.c:325-378` → `src/common/augabidulin.c:120-133` → `src/common/gabidulin.c:273-390` under `Implementations/Reference_Implementation/bag_piglet128/`. See `constant_time.md` for the secret/public classification and scope.
