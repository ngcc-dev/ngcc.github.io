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
