<!-- synchronized report: kem-07/report.md -->
Candidate: BRQC
Family: Code-based (rank metric)
Archive: [BRQC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BRQC.zip)

## kem-07-1: Secret-derived decoder pivots select memory addresses

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference implementations, all three parameter sets
Discovery: Moderate
Exploitation: Local cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

BRQC decryption computes `v-u*y` using private `y` and the public ciphertext (`src/brqc.c:277-288`). The Gabidulin decoder chooses pivot `next` from discrepancies in that word, then uses `next` as the load/store index of `u0` and `u1` (`src/gabidulin.c:185-201`). Those addresses vary with a secret-key-derived intermediate. The final KEM ciphertext comparison is masked, but it executes after this leakage. No complete key recovery or remote timing channel is demonstrated.

### Reproducing

Inspect `src/kem.c:214`, `src/brqc.c:277-288`, and `src/gabidulin.c:185-201` under `Implementations/Reference_Implementation/BRQC-128/`; the same pivot code is present in BRQC-256/512. See `constant_time.md` for the fuller trace.
