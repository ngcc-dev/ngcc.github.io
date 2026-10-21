<!-- synchronized report: kem-25/report.md -->
Candidate: NEV
Family: Lattice-based (NTRU/RLWE hybrid)
Archive: [NEV.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NEV.zip) (SHA-256: `8105c6241a322661411e870a3087338f48f4f5c477a540387b800c08955cc7fd`)

## kem-25-1: Compressed NEV sets omit the implicit rejection required by their security argument

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Compressed NEV-C1-c, NEV-C2-c and NEV-C3-c; reference, AVX2, AArch64 and NEON implementations
Discovery: Trivial
Exploitation: The stated transform argument does not cover the submitted decapsulation behavior; no IND-CCA attack demonstrated
Credit: Yamin Liu and Tianyuan Xie
Date: 2026-10-01
Original source: [NEV team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UZPNPPDYL5APZLO573LFHXX2ZLPVLZDE/)

Section 4 presents three families of parameter sets, NEV-C-1/2/3* (compact,
with ciphertext compression), NEV-R-1/2/3 (recommended) and NEV-D-1/2/3
(DFR-oriented), and offers the uncompressed NEV-C-1/2/3 as an alternative to
compression. Its compression discussion states that the compressed sets
require an implicit-rejection strategy for the security proof. Normative
Algorithm 27, however, returns `bottom` when ciphertext verification fails,
the §5.10 description of NEV-KEM-CCA calls the construction a Fujisaki–Okamoto
transformation with explicit rejection, and that single decapsulation
algorithm covers all nine parameter sets; no implicit-rejection variant is
specified for the compressed ones. All four submitted implementation families
follow Algorithm 27: they compare the reconstructed ciphertext, copy the real
key only when the comparison succeeds, and return the failure flag without
assigning a pseudorandom rejection key (`cca.c:33–51`).

Thus the archived compressed KEMs expose explicit rejection while their stated
compression argument assumes implicit rejection. The inconsistency lies within
the specification itself, and the implementations conform to it; this is why
the finding is a Design-layer proof gap rather than an implementation defect.
Because Algorithm 27 is the normative decapsulation for every set, an
implicit-rejection compressed variant also requires an amended algorithm. The
recommended and DFR-oriented sets, the uncompressed NEV-C-1/2/3 sets, and the
main NEV-KEM-CCA explicit-rejection proof are outside this finding. For the
compressed sets, encryption has no separate randomness term on which the
explicit-rejection proofs' spreadness argument could rely. This is a
substantive proof-to-algorithm mismatch, but explicit rejection alone is not
an IND-CCA break and no candidate-specific key-recovery or distinguishing
attack is shown; the finding is therefore Medium / Proof gap.

In a second private communication relayed on 2026-10-02, the NEV team further
pointed to Remark 5 (printed pp. 15–16; physical pp. 18–19), which presents the
compressed sets only to demonstrate possible efficiency gains and favors the
uncompressed construction for standardization. That clarification reinforces
the limited affected scope; it does not resolve the archived compressed
variants' internal mismatch between §4 and their normative decapsulation
algorithm. The project's performance comparisons therefore use the recommended
NEV-R sets, while retaining the alternative measurements in the detailed
performance record.

### Proposed fixes

The [NEV team response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UZPNPPDYL5APZLO573LFHXX2ZLPVLZDE/)
proposes changing compressed-set decapsulation to implicit rejection. This
section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-25/reproduce_rejection_mismatch.py
```

The certificate checks the specification language and all 48 submitted
`cca.c` copies, including the three compressed sets in each implementation
family, and requires the explicit-return pattern.

## kem-25-2: The sspRLWE reduction treats correlated transformed error as spherical

Severity: Low
Status: Proof gap
Layer: Design
Affected: Theorem 1's general `k=4` sspRLWE hardness argument; all submitted NEV parameter sets use `k=4`
Discovery: Moderate
Exploitation: A stated distributional step in the hardness reduction is false; no distinguisher, decapsulation attack, or key recovery demonstrated
Credit: Haotian (NGCC PKC Forum sender), with ChatGPT assistance
Date: 2026-10-21
Original source: [Haotian's PKC Forum comment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/26RYY4RTBJ2JMXXVYOVQRSVPOVPM2F3Q/) and [harness issue #35](https://github.com/ngcc-dev/ngcc-harness/issues/35)
Follow-up source: [NEV team's acknowledgment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SERNKUKLVVPLBZVSZDFIB6YXWTFM7SQJ/)

Lemma 2 (printed p. 5) says that, for independent spherical discrete Gaussians
`X` and `E`, the error `Y = VX + E` is statistically close to a spherical
Gaussian with `γ² = α² + 2β²`, where `V` is multiplication by
`1 − x^(n/k)`. Theorem 1 (printed p. 10) uses that claim to pass its
transformed error to an sspRLWE solver. But the Gaussian shape matrix is
`α²I + β²VVᵀ`, and `VVᵀ = 2I − S − Sᵀ` for the negacyclic shift
`S = x^(n/k)`. At `k=4`, `S + Sᵀ` has nonzero off-diagonal entries, so this is
not the claimed spherical shape. The cancellation does hold at `k=2`.
Every submitted set uses `k=4`; the issue is therefore in the stated proof,
not merely an unused generalization.

The [NEV team acknowledges](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SERNKUKLVVPLBZVSZDFIB6YXWTFM7SQJ/)
the covariance miscalculation. It says a larger `γ` and an earlier hardness
argument with `γ² = α² + 4β²` can repair the reasoning. At `k=4`, the
eigenvalues of `VVᵀ` are `2 ± √2`, so a reduction choosing its own additive
error with shape `γ′²I − β²VVᵀ` can in principle recover a spherical target
for `γ′² = α² + (2 + √2)β²`, within that older `4β²` margin. This identifies
a concrete repair route, not a completed check of the discrete-Gaussian
smoothing conditions. The team says its concrete parameters were not chosen
from the erroneous constant; §8.4 uses Core-SVP/MATZOV estimates instead.
The loss is to the stated tighter proof, with no shown effect on the chosen
parameters or an attack on the submitted KEM, hence Low.

### Reproducing

```sh
python3 kem-25/reproduce_gaussian_shape_gap.py
```

The certificate checks the frozen lemma and theorem text, confirms the
submitted `k=4` setting, and computes the exact negacyclic matrix identity
and the `2 ± √2` spectrum at a small dimension. It does not establish the
repaired reduction or estimate security at the real parameters.
