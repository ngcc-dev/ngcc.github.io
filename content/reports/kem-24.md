<!-- synchronized report: kem-24/report.md -->
Candidate: MORNING-Scabbard
Family: Lattice (Module-LWR)
Archive: [MORNING-Scabbard.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/MORNING-Scabbard.zip) (SHA-256: `fdb6749116bddbb8a86074b9ab6f5f55d37540b92e3964906dede0b09c7faf4b`)

## kem-24-1: Encryption omits the specified rounding constant

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, scabbard128 and scabbard256
Discovery: Trivial
Exploitation: Exact specification/source mismatch confirmed; no cryptanalytic attack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Algorithm 10 forms encryption component `u` by adding the constant `h` before the `q`-to-`p` right shift, implementing nearest rounding. The scabbard128 and scabbard256 reference implementations omit `+h` and truncate instead. The scabbard512 source contains the specified addition and provides a direct comparison.

Re-encryption repeats the same altered operation, so functional KATs and the Fujisaki-Okamoto equality check remain internally consistent. Nevertheless, the ciphertext distribution and decryption-noise law differ from those used by the specification's correctness, decryption-failure, and IND-CPA analyses.

This is a confirmed implementation/specification mismatch in two of three parameter sets. No concrete distinguisher or key-recovery attack has yet been derived from the changed distribution, so the report does not claim a complete confidentiality break.

### Reproducing

This is a source review, not a runnable attack. Fetch the official archive and
compare the encryption-component `u` rounding in the three reference variants:

```sh
IDS=kem-24 ./download.sh
./extract.sh kem-24
for level in 128 256 512; do
  sed -n '60,72p' "kem-24/Implementations/Reference_Implementation/scabbard${level}/indcpa.c"
done
```

The `u` shift is at lines 69, 67, and 69 respectively; only scabbard512 adds
`h1` first. Compare Algorithm 10 in `kem-24/kem-24-spec.pdf`.

## kem-24-2: Unvalidated ciphertext length bypasses or overruns comparison

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: scabbard128, scabbard256 and scabbard512 reference and optimized decapsulation
Discovery: Trivial
Exploitation: An oversized supplied length reads past a fixed stack buffer; a zero length skips re-encryption comparison, with predictable secrets confirmed and a plaintext-checking oracle; the reporters' key recovery is not independently reproduced. Both require a caller-supplied length that contradicts the ciphertext buffer
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3VTQVWNN5WYL2NLZ34HKBH5IGKMPULVA/)
Follow-up source: [Cao et al.'s PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/B2RYPKXMBW55CE4HBVGTBUI4IQMO2PC7/)

Each `kem_dec` allocates `cmp[SCABBARD_CIPHERTEXTBYTES]` but passes the unvalidated `ct_len_bytes` to `verify(ct, cmp, ct_len_bytes)` (`KEM_scabbard128.c:111–124`; scabbard256 declares `cmp` at line 112). `verify.c:14–15` reads both arrays for that many bytes. With an actual ciphertext buffer longer than the fixed ciphertext size, this reads beyond `cmp`. Conversely, passing a full ciphertext buffer with `ct_len_bytes=0` compares no bytes, so a changed ciphertext bypasses the re-encryption rejection check. Both cases require a caller-supplied length inconsistent with the actual ciphertext; the latter is not a separate in-model attack. The forum post reports an AddressSanitizer reproduction on reference scabbard512; the source certificate checks the same path in all six reference and optimized trees.

A 2026-11-12 follow-up by Hao Yan, Yuhang Cao, Yao Tong and Qiaosheng Zhang works out the zero-length case. Decapsulation then returns `KDF(K(m)‖H(ε))` for the decrypted message `m`. For an all-zero buffer, `m` is a fixed public message, so the returned secret is computable from the public key; we confirmed this at all three levels. Equal returned secrets also mean equal decrypted messages. The post uses this plaintext-checking oracle with single-coefficient `u` values to recover the long-term secret in 3,168, 4,608 and 9,216 queries for the three levels; we did not run that recovery. Every step still needs a caller that passes a full attacker-chosen buffer with declared length zero, so the classification is unchanged.

### Reproducing

```sh
python3 kem-24/reproduce_implementation_findings.py --report-id kem-24-2
sh kem-24/reproduce_zero_length_ss.sh
```

The first command is a source certificate; the sanitizer result is the forum's observation. The second builds each reference level and requires `kem_dec` with `ct_len_bytes=0` on an all-zero buffer to return the secret predicted from the public key for eight fresh keys, while the full-length control is rejected. The key recovery is not reproduced.

## kem-24-3: The failure analysis omits the floored `v` residual

Severity: High
Status: Probable
Layer: Design
Affected: Scabbard-256 quantified; Scabbard-128 has a similar offset but was not modelled; Scabbard-512's residual is small
Discovery: Moderate
Exploitation: Measured noise supports a scalar model whose Scabbard-256 DFR lower bound is about 2^-66 as specified and 2^-43 as implemented, against the claimed 2^-125; no failure-based attack attempted
Credit: Hao Yan, Yuhang Cao, Yao Tong and Qiaosheng Zhang, Shanghai AI Laboratory, with GLM 5.3, Kimi 3.1 Pro and in-house model assistance
Date: 2026-11-14
Original source: [Cao et al.'s PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/B2RYPKXMBW55CE4HBVGTBUI4IQMO2PC7/)

Algorithm 10, line 8 (p. 11), compresses `v` by a right shift without a rounding constant, as all three reference trees do (`indcpa.c:77`, `:77`, `:79`). Decryption therefore sees a nonnegative residual, which for Scabbard-256 is uniform on `{0, 4, …, 508}`. The §1.5 noise term (p. 14) has no ciphertext-compression error, and the submitted DFR program models compression by nearest rounding (`joint_distribution_2d.c:114`). Table 7 (p. 19) claims δ = 2^-125 for Scabbard-256.

The forum post models one coefficient as 1,152 independent rounding-error/CBD(2) products plus that residual, and gives a surrogate full-ciphertext estimate 128p of 2^-58.2 with the specified `+h` on `u` and 2^-35.4 with the shipped truncation of kem-24-1. We reproduced that model exactly. Over the whole noise grid, the submitted Minal decoder (β = 0) rejects every symbol once either coordinate's noise leaves ±1024. Any one such coefficient therefore fails decryption, so its model probability bounds the DFR from below without any independence assumption: about 2^-66.1 as specified and 2^-42.9 as implemented.

We measured 2×10^8 noise coefficients per variant from 1.6 million honest encryptions under 6,400 keys. The mean offset was +255 in both variants (model +254), and the standard deviations agreed to 0.1%. Tails with thousands of events agreed within 3%, and the shipped tail at or above 800 (453 events) was 15% lighter than modelled. The specified variant's two events at or above 800 are merely consistent with the model's 1.1×10^-8. The failure probabilities themselves remain model extrapolations, hence Probable.

Even the lower bound misses the claimed δ by about 59 bits as specified. It makes Theorem 5's q_RO·δ term (p. 21) vacuous well before 2^80 random-oracle queries. Under §3.2.6's own failure-search model (p. 24), one failing valid ciphertext is also expected within about 2^66.1 decapsulation trials as specified and 2^42.9 as implemented, hence High. No failure-boosting or key-recovery attack was attempted. Scabbard-128's offset is about +250 against a two-dimensional decoder that was not modelled; Scabbard-512's residual is below 32.

### Reproducing

```sh
python3 kem-24/reproduce_dfr_vfloor.py
NGCC_LONG=1 python3 kem-24/reproduce_dfr_vfloor.py
```

The script checks the specification, source and DFR program, builds archived Scabbard-256 as shipped and with `+h` on `u`, and measures the noise of 160,000 encryptions per variant (1.6 million when long). It characterizes the submitted Minal decoder over the full noise grid. It requires the measured mean and spread to match the exact model, and tails within −20%/+25% wherever at least 400 events are expected. It then prints the model's lower bound and 128p. It does not measure a failure.

## kem-24-4: Scabbard-128 truncates three of every four public-matrix coefficients

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Scabbard-128 reference, optimized and Cortex-M4 implementations; Scabbard-256 and Scabbard-512 unpack correctly
Discovery: Moderate
Exploitation: Exact specification/source mismatch; the reporters' 4.7-bit Core-SVP reduction is not reproduced, and no attack is demonstrated
Credit: Hao Yan, Yuhang Cao, Yao Tong and Qiaosheng Zhang, Shanghai AI Laboratory, with GLM 5.3, Kimi 3.1 Pro and in-house model assistance
Date: 2026-11-14
Original source: [Cao et al.'s PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/B2RYPKXMBW55CE4HBVGTBUI4IQMO2PC7/)

`SampleMatrixUD` (p. 8) fills `A` through `BytesToPoly` (Algorithm 2, p. 7), giving uniform 14-bit coefficients for q = 2^14. Scabbard-128's `poly_modq_frombytes` masks each shifted byte with `0xff` (`poly.c:17–19`), so three of every four coefficients lose their upper six bits and lie in 0..255. The function is identical in the optimized and Cortex-M4 trees, and `gen_a` uses it for every matrix entry (`polyvec.c:27`). Re-encryption and the KATs use the same code, so functional tests pass. A conforming implementation would not interoperate, and the security estimates assume a uniform matrix.

The forum post exploits the four-position periodicity: it selects 432 equations and treats the 144 secret coefficients met only by small entries as correlated noise. Its Core-SVP estimate falls from 2^127.6 for the ordinary primal attack to 2^122.9, below the claimed 2^128 (Table 7). That estimate, its noise-whitening heuristic and the final recovery step are not validated. A confirmed matrix-distribution defect with an unresolved attack consequence is Medium.

### Reproducing

```sh
sh kem-24/reproduce_matrix_truncation.sh
```

The witness checks the three Scabbard-128 unpackers, then builds archived `gen_a` at each level and compares eight matrices with Algorithm 2 applied to the same XOF output. At Scabbard-128, 30,609 of 41,472 coefficients differ, and positions 1–3 never exceed 255. Scabbard-256 and Scabbard-512 match exactly.
