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

Section 4.2 requires `H` to have only λ/2-bit collision resistance for a λ-bit security level. Both signing and verification reduce the message to `mu = H(tr, message)`; a collision for two messages under the same public `tr` transfers one valid signature to the other. Thus λ/2-bit collision resistance is insufficient to justify λ-bit EUF-CMA security. This is a requirement/proof gap, not a demonstrated forgery against an instantiation using a sufficiently collision-resistant hash.

The specification also chooses the contest's SM3-based `pseudoXOF` for its canonical 512-bit implementation over SHAKE256, reasoning that SHAKE256's 512-bit capacity limits its collision security to 256 bits. But `api/auxfunc.h` explicitly says `pseudoXOF` is for correctness verification and does not guarantee security. The reference pseudoXOF's 256-bit chaining state permits a generic ≈2^128-work message collision, but that observation concerns the evaluation primitive; it is not a break of the separate SHA3/SHAKE implementation or a secure replacement. A production hash choice needs an explicit collision-security argument at the claimed level.

### Reproducing

Inspect §4.2 of `sign-16-spec.pdf` for the λ/2 requirement and the canonical hash choice. In `sign.c` and `hash_domain.h`, both signing and verification bind the message only through `mu`; `api/auxfunc.h` states the contest primitive's security limitation. No full-size collision search was attempted.
