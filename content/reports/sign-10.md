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
