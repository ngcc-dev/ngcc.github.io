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
python3 security/design_parameter_audit.py --report-id kem-11-1
```

The check verifies the source constants and deterministic expansion against physical PDF pages 9, 12, 16, and 25.

## kem-11-2: The Biased-MLWR reduction does not instantiate the concrete small-secret sets

Severity: Medium
Status: Proof gap
Layer: Design
Affected: All four COMPASS-KEM parameter sets
Discovery: Moderate
Exploitation: Proof gap; no distinguishing or key-recovery attack demonstrated
Credit: Make
Date: 2026-10-02
Original source: [Make's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VQEI56DFEV7TIEGRXDN6O4P2T6DZ66DE/)

COMPASS-KEM's IND-CPA proof states Theorem 2 on physical p. 20 and uses Biased MLWR for its Game 2-to-Game 3 transition on p. 21. Definition 2 instead defines that problem with a uniform secret, and Theorem 1 relies on a uniformly random bounded component satisfying its leftover-hash-lemma inequality (physical pp. 16–17). Concrete encryption samples `r` from `CBD_eta` with `eta` in `{2,3,4}` (Algorithm 2, physical p. 14; Table 1, p. 18; `indcpa.c:336–337`). The submission gives no reduction from these concrete distributions to the stated assumption.

Further extension to Make's analysis: even granting each concrete coefficient the greater entropy of a uniform draw over its full `2 eta + 1` support leaves the displayed inequality short by 6,307, 7,121, 14,629 and 14,357 bits at the 128-, 256-, 384- and 512-bit sets. This quantifies a missing proof bridge, not an attack; the heuristic lattice estimates are separate.

### Reproducing

```sh
python3 kem-11/reproduce_biased_mlwr_gap.py
```

The certificate extracts the theorem's condition, checks each implementation's parameters and CBD call, and evaluates the optimistic entropy bound.
