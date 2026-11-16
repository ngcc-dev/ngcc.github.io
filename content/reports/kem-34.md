<!-- synchronized report: kem-34/report.md -->
Candidate: Rudraksh2
Family: Lattice-based KEM
Archive: [Rudraksh2.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Rudraksh2.zip) (SHA-256: `569d526cf7abe38393f69a4513686fa86a0c3b3033cc225b84cc107b20b17b98`)

## kem-34-1: Rudraksh2-128 has a 2^64-iteration generic search before oracle costs

Severity: Info
Status: Proof gap
Layer: Design
Affected: Rudraksh2-128-I; the same 128-bit message dimension is specified for Rudraksh2-128-II
Discovery: Trivial
Exploitation: None demonstrated below the 80-bit target; oracle and other quantum costs are unbounded here
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

Rudraksh2-128 samples a 16-byte encapsulation message `m`, then derives both the session key and the public encryption randomness as `G(m || H(pk))` (`params.h:41–50`, `KEM_lwekem128.c:73–97`). Given a ciphertext and public key, a candidate message is publicly testable by recomputing the encryption. Generic Grover search therefore needs about `2^64` such oracle iterations. This is below the set's nominal 80-bit quantum exponent if one counts oracle calls alone, but each oracle must implement and uncompute the full public encryption test. The NGCC call does not specify the quantum cost metric precisely, and no gate-level estimate establishes total work below `2^80`; this is an informational cost-model observation, not a vulnerability. The observation remains after replacing the contest placeholder XOF with an ideal primitive of the same dimensions.

The witness resets the deterministic test generator to recover the encapsulator's `m`, then reconstructs all 32 session keys as `G(m || H(pk))` without using the secret key or ciphertext. It demonstrates the public reduction but does not run the generic `2^64` search.

### Reclassification

Reclassified from Medium to Info on 2026-10-13: the 2^64 iteration count is unchanged, but no complete below-target quantum attack cost is established.

### Reproducing

```sh
make -C kem-34 reproduce-message-space
python3 kem-34/reproduce_parameters.py
```

## kem-34-2: Cortex-M4 uses an incompatible Minal decoder constant

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rudraksh2-128 and -256 Cortex-M4 implementations
Discovery: Trivial
Exploitation: Honest cross-implementation sessions derive different keys
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

The Cortex-M4 128- and 256-bit trees set `MINAL_BETA` to 0 (`minal.c:15`), whereas the specification, reference, and optimized implementations use 220. This constant changes the two-dimensional error-correcting code. Cross-tests reproduced zero matching keys in 200 sessions in each direction between Cortex-M4 and reference code; Cortex-M4 self-tests succeeded, and changing only the constant to 220 restored 200/200 interoperability in both directions. This is an availability/interoperability defect, not a confidentiality break.

### Proposed fixes

The original post proposes changing `MINAL_BETA` to 220 in the Cortex-M4 128- and 256-bit implementations.

### Reproducing

```sh
python3 kem-34/reproduce_parameters.py
```

The compact witness verifies the conflicting constants in the archived trees. The original package contains the full cross-implementation experiment.

## kem-34-3: KEM entry points ignore caller-declared buffer lengths

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rudraksh2 reference implementations
Discovery: Trivial
Exploitation: Out-of-bounds read from a caller-supplied short buffer
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

`kem_enc` and `kem_dec` accept public-key and ciphertext lengths but never inspect them, and `kem_dec` likewise ignores the supplied secret-key length. They instead read the compile-time sizes (`KEM_lwekem128.c:73–99,102–144`). Passing `kem_dec` an allocation one byte shorter than the normal 912-byte ciphertext and its true length of 911 produces an AddressSanitizer heap-buffer-overflow read at `poly.c:105`, reached through `indcpa.c:121`. No disclosure, write, or control-flow impact is demonstrated.

### Proposed fixes

The original post proposes validating caller-supplied lengths before accessing the public key or ciphertext.

### Reproducing

```sh
make -C kem-34 reproduce-length-read
```

## kem-34-4: Rudraksh2-II's modulus cannot support its specified NTT

Severity: Info
Status: Confirmed
Layer: Design
Affected: Rudraksh2-128-II, -256-II, and -512-II specifications
Discovery: Trivial
Exploitation: The specified NTT cannot be realized for these parameters; no security consequence is shown
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

The specification requires a primitive `2n`-th root of unity in `Z_q` for its negacyclic NTT. Every `-II` set uses `q=4001`, but `q-1 = 4000 = 2^5 * 5^3`; the largest supported negacyclic-NTT degree is therefore 16. The specified degrees are 64, 128, and 256, so none has the required root. The submission supplies no `-II` implementation. The polynomial ring itself remains implementable by a different multiplication method. This is a realization note, not a security vulnerability: no submitted `-II` implementation fails, and no attack or availability failure is shown.

### Reproducing

```sh
python3 kem-34/reproduce_parameters.py
```

## kem-34-5: Dual-hybrid attacks put Rudraksh2-512-I below its target

Severity: Critical
Status: Probable
Layer: Design
Affected: Rudraksh2-512-I
Discovery: Moderate
Exploitation: Estimated 2^495.5 operations for key recovery (MATZOV dual-hybrid, lattice-estimator gate-count model); not executed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-31

The Rudraksh2-512-I public key is an uncompressed MLWE sample with `ℓn = 2048`, `q = 7681` and CBD₂ secret and error (`lwekem512/params.h`). Table 14 claims Core-SVP 2^512 and 2^527 gates, and §3.2.5 states that the Core-SVP estimates meet the required security. The lattice-estimator's MATZOV dual-hybrid attack costs 2^495.5 in its default gate-count model and 2^482.1 in ADPS16 Core-SVP, below the primal attacks that Table 14 reflects. The estimate relies on the dual-attack heuristics the estimator adopts.

In Core-SVP the same attack gives 124.35 and 249.71 bits for Rudraksh2-128-I and -256-I, below Table 14's 129 and 267 and below their targets. In the gate-count model those sets are at 147.7 and 269.5 bits, above target, so they are not included in this rating.

### Reproducing

```sh
LATTICE_ESTIMATOR_PATH=../lattice-estimator sage -python kem-34/reproduce_dual_hybrid.py
```

The script requires lattice-estimator commit `53da598` and prints the best attack for each Rudraksh2-I set in both cost models. It takes about nine minutes.

## kem-34-6: Decryption decodes unreduced coefficients, unlike the decoder in the failure analysis

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rudraksh2-128 and -256 (q = 3329), reference and optimized implementations; Rudraksh2-512 (q = 7681) has no differing input
Discovery: Moderate
Exploitation: The submitted decoder and the analysed one disagree on 987 reachable coefficient pairs, all at least 429.1 from every codeword where the unique-decoding radius is 430.3; the effect on the failure-rate estimate is unresolved and no attack is demonstrated
Credit: Xifeng Jin (CertiK), with AI assistance
Date: 2026-11-15
Original source: [Jin's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FEJ5GKNJBHHOE534A66QWT3E7TVPF6XZ/)

The submitted DFR program decodes with a copy of the Minal decoder that first reduces both coordinates modulo `q` (`dfr_analysis/minal.c:159–166`). The reference and optimized decoders have no such step and assume inputs below `q` (`lwekem128/minal.c:122–146`). Decryption does not supply that: `poly_sub` computes `barrett_reduce(a + 3q − b)` and hands the result straight to `poly_tomsg` (`poly.c:354`, `indcpa.c:426–429`). For q = 3329 this Barrett step returns values up to 3,689, and about 10.5% of subtraction results are at or above `q`.

The forum post gives the pair (2914, 3443), which the submitted decoder maps to symbol 10 and the analysis decoder to 0. It reports 26 and 64 differing messages among 10,000 random well-formed ciphertexts at the two levels, and none among 1,000 honest ones. We reproduced the pair and enumerated every reachable case. Of the 2,359,857 reachable pairs with a coordinate at or above `q`, 987 decode to a different symbol than their reduced form. None of them is closer than 429.1 to any codeword, and half the code's minimum distance is 430.3, so the disagreement sits in a thin band at the edge of the unique-decoding radius and beyond it. Fifty of the pairs lie just inside that radius; there the shipped decoder returns the nearest codeword and the reduced decoder does not. Over all 987 pairs the shipped decoder returns the nearest codeword 779 times and the reduced decoder 207 times. At q = 7681 no reachable pair differs.

The failure analysis thus does not model the shipped decryption exactly. The mismatch is confined to points at least 429.1 from every codeword. Its effect on the submitted failure-rate estimate remains unresolved; no revised failure rate was computed.

### Reproducing

```sh
sh kem-34/reproduce_decoder_representatives.sh
```

The witness checks the two decoders and `poly_sub` in source, then builds the archived reference decoder at each level and compares it on every reachable non-canonical pair with the same decoder on reduced inputs. It requires 987 differing pairs at q = 3329, none nearer than 429.1 to any codeword against a half minimum distance of 430.3, 50 of them inside that distance, the nearest-codeword counts 779 and 207, the pair (2914, 3443) decoding to 10 and 0, and no differing pair at q = 7681.

## kem-34-7: A failed hash leaves the previous session key in encapsulation

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Rudraksh2 128, 256 and 512, reference and optimized implementations (Cortex-M4 identical by source)
Discovery: Moderate
Exploitation: If one hash allocation fails, encapsulation returns success with the previous call's shared secret, which an earlier recipient already holds; no remote way to force the failure is shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; stale-key consequence and witness by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-16
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/B7H75R23EOSR65ZDPQHAZ6WWVXK4NFYR/)

`kem_enc` keeps the key and coins in an uninitialised stack array `kr` (`KEM_lwekem128.c:80`) and fills it with `hash_g` (`:87`), a macro for the contest's `pseudoXOF` whose status is not checked (`symmetric.h:12–15`). When the helper's internal allocation fails it returns without writing `kr`. Encapsulation then encrypts under, and returns as the shared secret (`:97`), whatever the stack held, and returns 0.

In the witness one process encapsulates to Mallory and then to Bob with that allocation failing. The stale `kr` is the previous call's, so the key returned for Bob equals the key Mallory decapsulated, in all six x86 builds. Without the fault, and when the stack is overwritten between the two calls, Mallory's key does not match. The reused value depends on the call sequence and on the compiler's stack layout.

The failing allocation is a fixed-size buffer inside the contest helper. KEM input sizes are fixed, so a caller cannot choose it, and no remote way to force the failure is shown; memory pressure or a resource limit is needed. The candidate's defect is discarding the helper's status and returning success. A demonstrated session-key exposure under these preconditions is High.

### Reproducing

```sh
sh kem-34/reproduce_stale_encaps_key.sh
```

The witness wraps `malloc` to fail the third allocation of the encapsulation and requires Mallory to predict the Alice–Bob key in that run only.
