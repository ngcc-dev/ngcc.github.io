<!-- synchronized report: sign-10/report.md -->
Candidate: Facto-DSA
Family: Multivariate (cubic factorisation)
Archive: [Facto-DSA.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Facto-DSA.zip) (SHA-256: `b3de38fcc2d92ce83290d17cb250dde61f95d3326a49ada36fad3c578f2fc509`)

## sign-10-1: The hidden zero subspace has an unpriced algebraic recovery path

Severity: High
Status: Lead
Layer: Design
Affected: Facto-DSA-128, -256, and -512 security estimates
Discovery: Non-trivial
Exploitation: Full-size costs are extrapolated; approximately 2^55, 2^96, and 2^185 under the observed solving-degree model
Credit: Kris Kwiatkowski <contact@amongbytes.com>
Date: 2026-09-22
Original source: [ngcc-harness PR #3](https://github.com/ngcc-dev/ngcc-harness/pull/3)

The specification prices recovery of one nonzero vector in `K2 = ker(L2)` as an unstructured `q^n` search. But `K2` is an `n`-dimensional linear subspace contained in the zero locus of the public homogeneous cubic map. A random `(n+1)`-dimensional linear subspace of the `2n`-dimensional ambient space must meet `K2` nontrivially. Restricting the public map to it therefore gives `m` cubic equations in `n` affine variables with a guaranteed rational solution, which can be attacked algebraically rather than by guessing ambient points.

The submitted `build_public_key()` directly constructs `Q(L1*z)+R(L2*z)`, multiplies it by `Y=L2*z`, and applies the public output map `T`, confirming that the source has the structure used by the attack. The supplied specification-derived implementation reproduces the submitted parameter sizes and signing behavior, and confirms at full dimensions that `K2` has dimension `n` and the public map vanishes on it. Public-key-only reduced experiments recover the exact secret `K2` for `n=5,6,7`; the `n=7` instance reached solving degree 8 and completed in about 349 seconds in this review. Reduced `s=1` experiments then recover the coordinate separation, hidden quadratic space, symmetriser, and an equivalent triangular central map.

If solving degree remains `n+1`, the specification's own cubic-linear-algebra model gives `3*log2(binomial(2n+1,n+1))`, or approximately 55.3, 96.2, and 184.9 bits. This is not yet a confirmed submitted-size break: the degree pattern is extrapolated, Facto-DSA-128 has the less-overdetermined `s=6` shape, no full-size solve was run, and the final rational-normal-curve/GRS container identification needed for a working forgery was not implemented. The result nevertheless invalidates treating `q^n` search as the only structural recovery model and warrants a new full-scale algebraic analysis.

### Reproducing

The specification-derived attack code was submitted in [ngcc-harness PR #3](https://github.com/ngcc-dev/ngcc-harness/pull/3).

```sh
make -C sign-10/cryptanalysis
make -C sign-10/cryptanalysis test

# Optional larger reduced instance; about six minutes on the audit host.
sign-10/cryptanalysis/build/attack1 7 12 1 12
```

## sign-10-2: The public key yields a universal signing trapdoor

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Standard Facto-DSA-128 parameter set
Discovery: Non-trivial
Exploitation: Seconds to recover an equivalent trapdoor, then below one second per message in the submitted experiments
Credit: MingLLuo (GitHub @MingLLuo), with AI assistance disclosed by the submitter
Date: 2026-09-22
Original source: [GitHub issue #5](https://github.com/ngcc-dev/ngcc-harness/issues/5)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §3](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

Facto-DSA's public cubic map has a derivative space of dimension 165 inside the 210-dimensional space of quadratic forms. The 45 missing dimensions expose the hidden `X/Y` variable separation by linear algebra. In the recovered coordinates, another linear solve removes the mixed block and reveals the `n`-dimensional quadratic space; rank-one points recover a certified flag in which that space is triangular.

For Facto-DSA-128, slicing only the `Y` variables then reduces public inversion from 13 cubics in 20 variables to `f=m-n=3` equations of degree at most 10 in three variables. Solving this system, applying the signer's rescaling, and inverting the recovered triangular map gives an equivalent signing trapdoor using only the public key. It does not recover the submitter's original secret basis and needs no signing oracle.

An independent run against the pinned public key that the attack repository identifies as the first official 128-bit KAT key produced a 40-byte signature in 6.4 seconds with 58 MiB peak resident memory. The unmodified submitted `sig_verify` returned 0 for that signature and -1 after flipping one signature bit. This checkout omits the original KAT text, so the local reproducer validates the artifact hash and submitted verifier but cannot independently establish that public key's KAT provenance. The flag search is randomized and has exponential worst-case cost; the submitter reports 4--76 seconds over runs. The official 256- and 512-bit sets are not broken by this route because their reduced systems retain 15 and 30 variables respectively.

### Reproducing

The local target downloads hash-pinned artifacts from attack commit `bd9d4ce38ed2b78daf57093556ef2e866bbc2264`, then checks the forgery and negative control with this repository's submitted verifier:

```sh
make -C sign-10 reproduce-forgery
```

For the complete public-key recovery and fresh forgery, use the [pinned attack library](https://github.com/MingLLuo/facto_dsa_ngcc_round1/tree/bd9d4ce38ed2b78daf57093556ef2e866bbc2264): run `scripts/check_environment.py`, then `scripts/run_acceptance.py --source kat`. It requires NumPy, FLINT, msolve 0.10.1 or later, and a C compiler.

## sign-10-3: Unsalted hash targets permit below-level signature transfers

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Facto-DSA-128 and Facto-DSA-512
Discovery: Trivial
Exploitation: About 2^104.23 and 2^496.22 target evaluations at 50% collision success, respectively, followed by one signing query and a fresh-message signature transfer
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

Algorithms 10 and 11 hash `pkh || M` to the same unsalted vector `h` in `F_q^m`. The parameter table sets `q=65519` and `m=13,32,62`, giving target spaces of about 208, 512 and 992 bits. At 50% success, a collision between distinct messages under a fixed public key costs about `sqrt(2 ln 2)·q^(m/2)`: 2^104.23 for Facto-DSA-128 and 2^496.22 for Facto-DSA-512, below their 128- and 512-bit classical claims. Ask the signer for one of the colliding messages; its signature also verifies for the other, since verification has no later message-dependent input. The 256-bit set's corresponding cost is 2^256.23 and does not fall below its target.

The submitted Facto-DSA reference verifier follows this construction (`SIG_AlgorithmInstance.c:2065–2081`). The cost is an analytic birthday bound against the specified target space, not a completed full-size collision search. It persists with an ideal replacement for the contest `pseudoXOF`, because the vector space itself is too small.

### Reproducing

```sh
python3 sign-10/reproduce_target_width.py
```

The certificate checks the source dimensions and the shared unsalted signing/verifying input, then recomputes the three collision bounds.

## sign-10-4: Honest signatures fix values of secret linear forms

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Facto-DSA-128, -256 and -512 reference implementations (executed); the optimized and resource-constrained implementations contain the same signing path (source)
Discovery: Moderate
Exploitation: Secret-dependent signature distribution measured with the signer's secret map; no key recovery or forgery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Algorithm 10 (physical p. 12) completes a target, factors it into `A0·Y0` and then searches rescalings `lambda` in `F_q^*` (lines 17–19) before triangular inversion of `Q(X) = W`. Section 1.4.4 d) (p. 13) leaves the rescaling order as an "implementation rescaling schedule", and the signing-success analysis (p. 19) assumes the full set `Lambda = F_q^*`. Write `XY = S z` for a signature `z`, where `S` is the secret `2n x 2n` map. The reference signer builds `b` from `poly_one` times monic factors (`SIG_AlgorithmInstance.c:1071`), so `Y0` is monic. It sets `Y = scale^-1 · b` (`:1835`) and tries `scale = 1` first, before any random scale (`:2023–2024`). Whenever that first attempt succeeds, `Y_{n-1} = (S z)_{2n-1} = 1` exactly. A uniform preimage would make this value uniform on `F_q^*`, that is equal to 1 with probability `1/(q-1) = 1.5e-5`.

A second secret form is fixed in every signature. `invert_Q_rec()` takes the root `(f_sqrt(Delta) - beta)/(2a)` first (`:1450–1452`) and the negated root only on backtracking (`:1455–1459`), and `f_sqrt()` returns `Delta^((q+1)/4)` (`:167–172`), which is always a quadratic residue. Every `Q_i` is homogeneous, so at level 0 the negated-root subtree fails exactly when the principal one fails. Hence the quadratic character `chi(2 a_0 X_0) = +1` in every signature, where `a_0` and the first row of `S` are secret.

Through the public signing API, `(S z)_{2n-1} = 1` held in 6.5% of 2,000 Facto-DSA-128 signatures, 4.7% of 300 at -256 and 1 of 60 at -512, and `chi(2 a_0 (S z)_0) = +1` held in every signature at all three levels. The same signatures evaluated under an unrelated key's secret map gave no hits and a character of +1 about half the time, as did a fixed random public form. Every honest signature verified. The signer is therefore not the uniform preimage sampler assumed by the specification's signing analysis, and each signature discloses a fixed value of one secret linear form with a few per cent probability and one bit of another deterministically.

The measurement uses the secret key as a test statistic. No public-only extraction or key-recovery route is known: recovering the fixed row from a few per cent of inliers is a noisy hyperplane problem, and the character leak is a hidden-linear-form problem with no known efficient solver. The specification's Assumption 1 (p. 22) states hardness given a signing-preimage oracle, so this contradicts no stated theorem; it shows that the oracle discloses deterministic secret structure. The same code paths appear in the optimized and resource-constrained implementations, which were not executed.

### Reproducing

```sh
python3 sign-10/reproduce_signature_leak.py
```

The script checks the five source patterns in all nine trees, then signs 2,000, 300 and 60 messages through `sign-10/lib/libFacto-DSA-*.so` and evaluates the secret forms (about 15 seconds). Its controls are honest verification, rejection of mutated signatures and changed messages, an unrelated key's secret forms and a random public form; `NGCC_LONG=1` signs 8,000, 1,000 and 300 messages.
