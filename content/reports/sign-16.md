<!-- synchronized report: sign-16/report.md -->
Candidate: Octarine
Family: Lattice-based signature
Archive: [Octarine.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Octarine.zip)

## sign-16-1: The stated hash requirement is too weak for the EUF-CMA target

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Octarine specification, all parameter sets
Discovery: Moderate
Exploitation: Conditional signature transfer at the replacement hash's collision cost; no full-size attack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23
Follow-up source: [Mounir IDRASSI's issue #11](https://github.com/ngcc-dev/ngcc-harness/issues/11), [issue #13](https://github.com/ngcc-dev/ngcc-harness/issues/13)

Section 4.2 requires `H` to have only λ/2-bit collision resistance for a λ-bit security level. Both signing and verification reduce the message to `mu = H(tr, message)`; a collision for two messages under the same public `tr` transfers one valid signature to the other. Thus λ/2-bit collision resistance is insufficient to justify λ-bit EUF-CMA security. This is a requirement/proof gap, not a demonstrated forgery against an instantiation using a sufficiently collision-resistant hash.

The specification also chooses the contest's SM3-based `pseudoXOF` for its canonical 512-bit implementation over SHAKE256, reasoning that SHAKE256's 512-bit capacity limits its collision security to 256 bits. But `api/auxfunc.h` explicitly says `pseudoXOF` is for correctness verification and does not guarantee security. The reference pseudoXOF's 256-bit chaining state permits a generic ≈2^128-work message collision, but that observation concerns the evaluation primitive; it is not a break of the separate SHA3/SHAKE implementation or a secure replacement. A production hash choice needs an explicit collision-security argument at the claimed level.

Follow-up analysis: [Mounir IDRASSI's GitHub issue #11, 2026-09-23](https://github.com/ngcc-dev/ngcc-harness/issues/11) details the state-collision signature-transfer mechanism and demonstrates it in a reduced-state model. It explicitly does **not** produce a collision or forgery with the unmodified SM3 implementation. [Issue #13](https://github.com/ngcc-dev/ngcc-harness/issues/13) gives a separate 344-bit descriptor for the correctness-only SM3 secret expansion; it is not treated here as a break of a secure hash instantiation.

### Reproducing

Inspect §4.2 of `sign-16-spec.pdf` for the λ/2 requirement and the canonical hash choice. In `sign.c` and `hash_domain.h`, both signing and verification bind the message only through `mu`; `api/auxfunc.h` states the contest primitive's security limitation. No full-size collision search was attempted.

## sign-16-2: Polynomial solutions of the relaxed Octarine-512 SIS estimates

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Octarine-512 Appendix A estimator instances, both hash families
Discovery: Moderate
Exploitation: Polynomial time for the relaxed random-matrix problem; no signature forgery
Credit: Mounir IDRASSI <mounir@amcrypto.jp>
Date: 2026-09-23
Original source: [GitHub issue #12](https://github.com/ngcc-dev/ngcc-harness/issues/12)

Appendix A estimates ordinary homogeneous SIS at modulus `q=2^24`, with 5,120 rows and either 10,240 or 15,360 columns. Its 512-level infinity-norm bounds are 4,194,306 (SUF) and 4,947,969 (EUF). Split the first 10,240 columns into square blocks `B,C`. If both blocks are invertible modulo 2, two binary linear solves produce a nonzero `w` with `[B C]w=0 mod 4`; then `X=(q/4)w` solves the full-modulus SIS equation with norm exactly 4,194,304, below both estimated bounds. For independent random blocks, the invertibility condition has constant probability, about 0.0834.

I independently verified the submitter's complete 5,120-row certificate: all residuals vanish modulo 4, the vector has 7,683 nonzero coordinates and the stated norm, and a modified-vector control fails. This invalidates the hardness estimate for those *relaxed* SIS instances. It does **not** forge a signature: the actual SUF extraction requires the response difference to have norm strictly below 4,193,956, which this certificate violates; the EUF challenge also has structural constraints erased by the estimator.

### Reproducing

The script downloads the hash-pinned [published certificate](https://github.com/amcrypto-jp/octarine-cryptanalysis/blob/v1.0.1/data/sis_witness_5120.npz) and requires NumPy:

```sh
python3 sign-16/reproduce_relaxed_sis.py
```

Use a Python with NumPy installed; on a system where only a mamba Sage environment provides it, run `mamba run -n sage python sign-16/reproduce_relaxed_sis.py`.
