<!-- synchronized report: kem-11/report.md -->
Candidate: COMPASS-KEM
Family: Lattice-based
Archive: [COMPASS-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/COMPASS-KEM.zip) (SHA-256: `8fc838488ac0849d4c6afd161f8b9742c7a8b9a330bc3b79df70ced7e2d1d5e2`)

## kem-11-1: COMPASS-KEM-384 and -512 use a 256-bit key-generation root

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: COMPASS-KEM-384 and COMPASS-KEM-512 reference implementations and specification
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The COMPASS-KEM algorithms define both the initial key-generation seed and the shared key as `n`-bit values. The submitted COMPASS-KEM-384 and COMPASS-KEM-512 implementations instead fix `SYMBYTES` and `SSBYTES` at 32 bytes.

The entire IND-CPA key pair is a deterministic function of one 256-bit `coins` value. There are therefore at most `2^256` generated public keys: enumerate the root, regenerate the public key, and compare it with the target to recover the corresponding secret key. The KEM output independently has at most 256 bits of delivered-key capacity.

This caps both implementations at 256 bits despite their respective 384- and 512-bit classical claims. The specification is internally inconsistent: Algorithm 1 requests an `n`-bit seed, while its implementation notes on physical PDF page 25 say that one could store only a “32-byte core seed” and rerun key generation. The submitted code follows the shorter interpretation.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check verifies the source constants and deterministic expansion against physical PDF pages 9, 12, 16, and 25.
