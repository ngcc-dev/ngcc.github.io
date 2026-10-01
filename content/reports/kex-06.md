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

## kex-06-2: Static-key reconciliation admits an active reaction-recovery path

Severity: High
Status: Lead
Layer: Design
Affected: MAMBA-NIKE-128 and -384 recovered with the raw-reconciliation oracle; the same unvalidated static-key path is present in all sets
Discovery: Hard
Exploitation: Complete MAMBA-NIKE-128 and -384 static-key recovery in 71 raw-reconciliation queries; the deployed hashed-key route is estimated at about 2^15 reactions but is not implemented or benchmarked
Credit: Zhenyu Xiong and Mingsheng Wang
Date: 2026-09-27
Reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §6](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

The static responder applies D4 reconciliation to an unvalidated attacker-chosen one-pass message under the same long-term secret. Its intermediate product is linear in that secret, while the dither is derived from the attacker's public `mu`. Chosen monomial messages therefore turn each reconciliation group into a small lookup problem over four secret coefficients.

The pinned artifact uses the reference implementation's `STATISTICAL_TEST` path, which returns the raw reconciliation bits rather than their hash. A fixed 71-query probe set recovers complete MAMBA-NIKE-128 and -384 secrets; local runs recovered 1/1 and 5/5 keys. That validates the candidate-specific algebra and raw reaction oracle. It does **not** validate the artifact's claimed roughly `2^15` route from the deployed API's single hashed-key confirmation bit, and the specification's Appendix B explicitly limits its theorem to passive security and disclaims active/key-reuse security. The NGCC [Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/tT7TSQiz.pdf) §1(1), however, require key-exchange protocols to satisfy a suitable security model such as CK, CK+, eCK, or eCK-PFS. For those reasons this is a High Lead and a NIKE category/security-model mismatch, not a claimed break of the stated passive theorem.

An actively secure static NIKE cannot reconcile arbitrary unauthenticated peer input under a reused secret and then expose key confirmation. The construction needs transcript binding and an active-security transform rather than only the passive theorem it currently supplies.

### Reproducing

```sh
sh kex-06/reproduce_reaction_recovery.sh
```

The wrapper fetches the [pinned artifact](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/e724a12a834bfc063dc0d2959d864842f269eb1e/mamba-nike-key-recovery), builds it against the archived reference sources here, and runs the demonstrated 128- and 384-bit raw-oracle recoveries.

## kex-06-3: Reconciliation leakage makes the passive-security bound vacuous

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Passive-security proof for all five MAMBA-NIKE parameter sets
Discovery: Moderate
Exploitation: The stated real-or-random bound is approximately one; no efficient distinguishing or key-recovery attack demonstrated
Credit: Manoj Gyawali, with AI assistance
Date: 2026-10-01
Original source: [Gyawali's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/F3VFGJZMVVPWZMHYK25ID4RAHEDI4X4K/)

Definition 6.2 defines `epsilon_rec` as the statistical distance of the initiator's raw key from uniform after conditioning on the complete public transcript. Given that transcript, the parties' independent private randomness remains independent, so their raw keys are conditionally independent. If their disagreement probability is `rho_key`, this implies

`epsilon_rec >= 1 - rho_key - 2^-kappa`.

Consequently the `epsilon_rec + rho_key` term in Theorem 6.1 and Theorem B.1 is at least `1 - 2^-kappa`: essentially one for the submitted `kappa=256` and `512`. The displayed bound therefore establishes no nontrivial passive real-or-random security, and Appendix C.1 analyzes agreement errors rather than the statistical distance needed to close this gap.

This is a proof failure, not evidence of computational insecurity. No efficient distinguisher or recovery attack follows from the argument, so the finding is Medium rather than Critical.

### Reproducing

```sh
python3 kex-06/reproduce_reconciliation_bound.py
```

The script checks the submitted dimensions and prints the unavoidable lower bound on the proof's additive term.
