<!-- synchronized report: sign-16/report.md -->
Candidate: Octarine
Family: Lattice-based signature
Archive: [Octarine.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Octarine.zip) (SHA-256: `7044d22735d39f902df35dd7d8d77c850cd296c81517e8c19134a2f9d006655a`)

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

## sign-16-3: A failed hash allocation leaves the previous digest in the verifier

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Octarine-128, -256 and -512 SM3 reference and optimized implementations; the SHAKE additional implementations do not allocate there
Discovery: Moderate
Exploitation: If a hash allocation fails after an earlier verification in the same process, a signature on the earlier message verifies for a new message
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XLA3HRWS6XUK4IH2N6ZXU6YQIYOQD65W/)

Verification hashes the message representative µ and then the challenge seed (Algorithm 3, p. 26, Verify lines 5 and 9). `RRLWR_SIGN_HASH_MU` checks its own `malloc` (`hash_domain.h:200–203`) but ignores the status of the `pseudoXOF` call it makes (`:213`), and `RRLWR_SIGN_HASH_CH` does the same (`:255`). The outputs `mu_w1` and `ctildep` are uninitialised stack buffers (`sign.c:308,312`), and `pseudoXOF` returns before writing when its internal copy fails.

With the reference code at all three levels, a signature on message A was accepted for a different message B when `pseudoXOF`'s copy of the µ input (for 64- and 5,000-byte messages) or of the challenge input (947, 1,459 or 2,099 bytes) failed during the verification of B, immediately after verifying A. Without the failure, or with the stack scrubbed between the calls, B was rejected. The optimized trees behave the same.

The µ copy is sized by the message; the checked outer copy of nearly the same size is live at the same time, so only the inner one must fail. The candidate's defect is discarding the hash status and returning success. Demonstrated acceptance of a signature for a different message is High.

### Reproducing

```sh
sh sign-16/reproduce_stale_digest.sh
```

The witness checks the unchecked calls in the six SM3 trees, then builds each reference level with `malloc` wrapped so that exactly one allocation of the targeted size fails, and requires the signature on A to verify for B only in that case.

## sign-16-4: A failed mask-seed allocation makes signing reuse the previous mask and leaks the signing key

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Octarine-128, -256 and -512 SM3 reference and optimized implementations
Discovery: Moderate
Exploitation: If one fixed 318-byte allocation fails during signing, the call returns a valid signature made with the previous call's ρ″; s1 follows from it and the previous signature, and the rebuilt key signed a fresh message; no remote way to force the failure is shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19

Signing derives the mask seed ρ″ from K, fresh randomness and µ (Algorithm 3, p. 26, Sign line 4) with `RRLWR_SIGN_HASH_RHOPP` (`sign.c:186`), which drops the `pseudoXOF` status (`hash_domain.h:237`) and returns nothing to check. When `pseudoXOF`'s 318-byte copy fails, `rhopp` keeps the previous call's value, so the masks y repeat under a different message and challenge.

With the reference code at all three levels, eight rounds of one ordinary signature followed by one faulty signature gave faulty signatures that verify. Solving z₂ − z₁ = (c₂ − c₁)·s1 from each pair, using public data only, gave the key's s1 in 6, 8 and 8 of 8 pairs. A key rebuilt from the public key and s1 signed a fresh message that the unmodified verifier accepted, and rejected for a changed message. Pairs of ordinary signatures gave no solution. The same relation holds in the optimized trees.

The failing allocation has a fixed size and is not chosen by the attacker; memory pressure or a resource limit is needed. Demonstrated key recovery is High.

### Reproducing

```sh
sh sign-16/reproduce_stale_mask.sh
```

The witness checks the unchecked hash in the six SM3 trees and wraps `malloc` to fail that copy once per faulty call.

## sign-16-5: A failed key-derivation allocation makes key generation return the previous key pair

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Octarine-128, -256 and -512 SM3 reference and optimized implementations; the SHAKE additional implementations do not allocate there
Discovery: Moderate
Exploitation: If one fixed 108-byte allocation fails during key generation, the call returns success with the previous call's key pair, whose secret key an earlier key holder already has; no remote way to force the failure is shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19

Key generation derives (ρ, ρ′, K) from the fresh seed ξ (Algorithm 3, p. 26, KeyGen line 2) with `RRLWR_SIGN_HASH_KDF` (`sign.c:65`), which drops the `pseudoXOF` status (`hash_domain.h:168`) and returns nothing to check. Its output `rho_rhoprime_K` is an uninitialised stack array (`sign.c:54`). When `pseudoXOF`'s 108-byte copy of the encoded seed fails, the array keeps the previous call's (ρ, ρ′, K), and `sig_keygen` rebuilds the same key pair from it and returns 0 (`:114`).

With the reference code at all three levels, a key generation with that allocation failing, immediately after an ordinary one, returned 0 with public and secret keys byte-identical to the previous ones. A signature made with the first secret key verified under the second public key, and was rejected for a changed message. An ordinary key generation gave a different key pair, and the same failure after the stack had been overwritten gave a key pair equal to neither. The optimized trees, built with their AVX2 flags, gave the same results.

The failing allocation has a fixed size and is not chosen by the attacker; memory pressure or a resource limit is needed. A key pair returned as new whose secret key an earlier caller already holds is High.

### Reproducing

```sh
sh sign-16/reproduce_stale_keygen.sh
```

The witness checks the unchecked derivation in the six SM3 trees and wraps `malloc` to fail that copy once.
