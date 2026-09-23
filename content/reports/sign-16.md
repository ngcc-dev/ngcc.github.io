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

An ideal replacement with the same specified input/output dimensions does not repair the weak *stated requirement*: the security argument must require collision resistance commensurate with the claimed EUF-CMA level. Attacks on the contest's correctness-only SM3 `pseudoXOF` internals are outside this finding.

Follow-up analysis: [Mounir IDRASSI's GitHub issue #11, 2026-09-23](https://github.com/ngcc-dev/ngcc-harness/issues/11) demonstrates state-collision signature transfer in a reduced-state evaluation model, not a full-size forgery. [Issue #13](https://github.com/ngcc-dev/ngcc-harness/issues/13) concerns correctness-only SM3 secret expansion; neither issue establishes a break of an ideal replacement.

### Reproducing

Inspect §4.2 of `sign-16-spec.pdf` for the λ/2 requirement. In `sign.c` and `hash_domain.h`, both signing and verification bind the message only through `mu`. No full-size collision search was attempted.

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
mamba run -n sage python sign-16/reproduce_relaxed_sis.py
```

The command uses this host's NumPy-equipped Sage environment; elsewhere, any Python with NumPy installed can run the script.
