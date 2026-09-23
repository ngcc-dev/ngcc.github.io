<!-- synchronized report: kex-06/report.md -->
Candidate: MAMBA-NIKE
Family: Lattice-based NIKE
Archive: [MAMBA-NIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/MAMBA-NIKE.zip) (SHA-256: `79b53ff726121ccb1ce970003c06b605e973c4e4f452dbe780e70cd4c40ca018`)

## kex-06-1: MAMBA-NIKE-384 and -512 use only 256 secret-seed bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: MAMBA-NIKE-384 and MAMBA-NIKE-512 reference implementations
Discovery: Trivial
Exploitation: Approximately 2^256 secret-seed trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The MAMBA-NIKE specification samples each static secret polynomial from the full centered-binomial distribution. The MAMBA-NIKE-384 and MAMBA-NIKE-512 implementations instead derive that polynomial deterministically from one 32-byte `noiseseed`.

For the public `rho` stored with a target key, an attacker can enumerate all `2^256` noise seeds, regenerate the secret polynomial and public value `b`, and compare `b` with the target. A match recovers the static secret. The independent `rho` seed is public and does not increase the secret-search exponent.

This limits both implementations to at most `2^256` secret-seed trials, below their respective 384- and 512-bit classical claims. It is an implementation/specification conformance break, not a limitation of the normative secret distribution.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check traces `noiseseed[32]` through `poly_getnoise` and checks the normative KeyGen description on physical PDF pages 7–15.
