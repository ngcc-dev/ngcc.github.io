<!-- synchronized report: sign-08/report.md -->
Candidate: DARTS
Family: Lattice-based
Archive: [DARTS.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DARTS.zip) (SHA-256: `1846cfe63f0cef83e2e0ca21f5dcadce3c4b16da33713957be6d156e2a9e6e95`)

## sign-08-1: The implemented message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: DARTS-512 reference and optimized implementations and specification
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

DARTS-512 claims 512-bit classical security and binds messages through the unsalted representative `mu = H1(pk, M)`. The submitted implementation emits only 64 bytes. A generic collision therefore costs about `2^256` evaluations and transfers a requested signature from one colliding message to the other.

The PDF names `H1` but does not define its output length. The concrete implementation ceiling is confirmed, while the missing length prevents classifying 64 bytes as a clean normative design parameter. This is an implementation security ceiling and a specification omission.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-08-1
```

The check verifies the DARTS-512 algorithm on physical PDF pages 4, 8, and 12–13 and traces its 64-byte `mu`.

## sign-08-2: The compression-consistency restart leaks an equivalent DARTS-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: DARTS-128 as specified and implemented; the other parameter sets were not tested
Discovery: Non-trivial
Exploitation: About 20–30 million public signatures, followed by seconds of CPU work
Credit: Bing Shi <roadicing@gmail.com>
Date: 2026-09-26
Original source: [Shi's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/62AUZI56IWGEN34OQTD6Z2U6APFMRYWC/) and [public proof of concept](https://github.com/roadicing/darts-key-recovery-attack/tree/5df01ac2b3e4b7a804fae5b3c5b4f8ad531cdaff)
Follow-up source: [Martin Feussner's independent DARTS-128 recovery](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/J7RWJSD6H5IBCXDBD2XSHKCKGARBT6TA/), [the DARTS team's confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3XGOCUUIBO5UJ5C4GQKIIWR3AHAQNI2X/), and [version 2.0 announcement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6V6TNUOGT6DIGDGNEONV7PVACXWUONM4/)

Step 9 of Algorithm 7 accepts every signing attempt when the hidden branch bit is `b=1`, but for `b=0` accepts only when `Comp_d(omega) = Comp_d(omega+c alpha)`. Because `omega=A round(y)`, this asymmetric restart tilts the joint distribution of the published challenge and rounded response by a small key-dependent multiple of the sparse secret. Shi separates that impulse train from a smooth fixed bias, then enumerates the few uncertain coefficients and checks candidates with the exact public relation `e=(q+1)/2 beta-A s mod q`, requiring ternary `e`.

We replayed the pinned PoC's accumulators from 20,000,000 DARTS-128 signatures. The collector derives them only from decoded public signature fields. The full data estimated 19,983,582 samples, measured a `656.87`-sigma signal, and recovered all secret polynomials after 40,342 public-relation candidates. The recovered bytes before the independent signing seed matched the submitted secret-key control exactly. Setting that irrelevant seed to zero still produced a fresh-message signature accepted by the untouched submitted verifier; changing one message byte was rejected. This is therefore equivalent signing-key recovery and an EUF-CMA forgery, not merely a distinguisher.

Feussner independently reports full DARTS-128 recovery and fresh-message forgery from 17,000,000 signatures using negacyclic normal equations, ternary classification, and Kannan/BKZ completion. The DARTS team confirms that both attacks exploit the same omitted factor `2` in Step 9.

### Proposed fixes

The [DARTS team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3XGOCUUIBO5UJ5C4GQKIIWR3AHAQNI2X/) proposes replacing the submitted `(1-b)c*alpha` comparison term by `(1-2b)c*alpha`. Its 2026-10-30 announcement says version 2.0 corrects Step 9 of Algorithm 7 and updates the corresponding implementation and test vectors. These proposals and reported changes are recorded without evaluating the revised candidate.

### Reproducing

```sh
make -C sign-08 exploit-key-recovery
```

The wrapper clones and verifies the pinned attack commit, builds its public-relation checker against this repository's archived DARTS-128 source, replays the published accumulators, and tests a fresh signature with the recovered key. It requires Git, a C compiler, and a Python interpreter with NumPy; set `NGCC_SAGE_PYTHON` when NumPy is available only in a Sage environment. The original 20-million-signature collection is not repeated.

## sign-08-3: Reference and AVX2 DARTS expand different public matrices

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: DARTS128, DARTS256 and DARTS512 reference versus AVX2 implementations
Discovery: Moderate
Exploitation: Honest signatures from either implementation fail verification in the other; no forgery or key recovery follows
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PHSEM2FMDUS6IKY4N3GQCIZLFJEWMIVK/)
Follow-up source: [DARTS version 2.0 announcement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6V6TNUOGT6DIGDGNEONV7PVACXWUONM4/)

The reference `poly_uniform` initially squeezes nine blocks and retains leftovers using `% 16` (`poly.c:917–945`). AVX2 initially squeezes seven blocks, then uses `% Q_BITS` in its scalar path and a separate four-way refill path (`poly.c:1266–1355`). These differences are consistent with divergent `ExpandA` matrices: the first-record public keys in the submitted reference and AVX2 KATs share their seedA prefix and diverge immediately afterward at all three tiers. The forum reports mutual rejection of honest cross-implementation signatures at all three tiers, 4/4 seeds, while each build verifies its own signatures. Our certificate confirms the divergent source paths, not that runtime experiment. The specification does not fix the `PolyUniform` squeeze schedule, so this is an implementation interoperability finding, not a design or forgery claim.

### Proposed fixes

The forum reports that changing AVX2's expansion read pattern restores reference-KAT verification. The DARTS team later announced that version 2.0 resolves consistency issues between the reference and optimized implementations, without identifying this ExpandA mismatch specifically. These proposals and reported changes are recorded without evaluating the revised candidate.

### Reproducing

```sh
python3 sign-08/reproduce_expanda_mismatch.py
```

## sign-08-4: AVX2 DARTS-512 samples its signing secret from 256 seed bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: DARTS-512 AVX2 implementation
Discovery: Moderate
Exploitation: At most 2^256 candidate secret samplings and public-key checks, far below the 512-bit claim; the full search was not run
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; key-search extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PHSEM2FMDUS6IKY4N3GQCIZLFJEWMIVK/)

DARTS-512 specifies a 64-byte master seed (Table 2, physical p. 13; Algorithm 6, physical p. 8). Its AVX2 key generator creates a 64-byte `seed_s` and calls `polyveckl_ternary_p` for all secret polynomials (`sign.c:50–65`). That sampler calls `poly_ternary_p`, which invokes `stream256_init` (`poly.c:1368,1388`). Source inspection shows that the AVX2 wrapper absorbs only 32 seed bytes (`symmetric.h:63–65`), whereas the reference sampler absorbs all 64. The packaged certificate does not execute either stream.

Consequently, the AVX2 signing polynomials have at most 2^256 possible seed-prefix sources. An attacker can enumerate them, apply the key-generation rejection test, and check the resulting public relation against `A0` in the public key (`sign.c:65–98`). A match supplies an equivalent signing secret; the independent signing-randomness key `K` can be chosen afresh. This is a concrete below-target search bound, not a practical completed search.

### Reproducing

```sh
python3 sign-08/reproduce_secret_seed_width.py
```

The certificate checks local submitted source files when present. With `--archive DARTS.zip`, or when local files are absent, it verifies the official archive's SHA-256 before checking the same source call chain. It does not run a native stream test or enumerate the 2^256 prefixes.

## sign-08-5: The sign byte of one attempt is reused as mask sign bits of the next

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: DARTS128, DARTS256 and DARTS512 reference implementations and AVX2 DARTS512; AVX2 DARTS128 did not show it and the NEON tree was not run
Discovery: Non-trivial
Exploitation: After a rejected attempt the mask is not uniform, and accepted signatures carry a measurable public bias in two response coefficients; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
`expandY` should return a mask and two independent bits `(b, b′)` (Algorithm 7, line 5, p. 9). `polyfixveclk_sample_hyperball` samples the mask polynomials with nonces `ni++`, then derives the byte holding `b` and `b′` from `seed ‖ ni` with the next, unused nonce, and returns `ni` without advancing it (`polyfix.c:256–261,288–299`). When the attempt is rejected, `sign.c:169` calls the function again with that counter, and the first Gaussian stream of the new mask starts from the same `seed ‖ ni`. Its first output byte, which was the previous attempt's `(b, b′)` byte, now supplies the sign bits of coefficients 0–7 of the first mask polynomial.

With the archived reference DARTS128, the sign of each of those eight mask coefficients equalled the corresponding bit of the previous attempt's byte in 200 of 200 trials. The rejection decision depends on `b` and `b′`, so the reuse survives into accepted signatures: over 40,000 verified signatures, response coefficient 1 of the first polynomial was negative 41.4% of the time and coefficient 0 48.5%, against 49.6–50.5% for coefficients 2–15.

The mask is therefore not uniform on the hyperball after the first attempt, and the security argument's rejection-sampling step does not apply as written. Whether the bias depends on the key was not examined and no recovery was attempted.

### Reproducing

```sh
d=sign-08/Implementations/Reference_Implementation/DARTS128
sed -n '256,261p' "$d/polyfix.c"; sed -n '288,299p' "$d/polyfix.c"; sed -n '169p' "$d/sign.c"
```

This is a source witness: the nonce use, the derivation of the sign byte from the unconsumed nonce, and the retry call. The match rates and signature frequencies came from a driver against the archived code and are not part of the witness.

## sign-08-6: Low-bits decoding accepts noncanonical fields, giving byte-distinct valid signatures

Severity: High
Status: Confirmed
Layer: Implementation
Affected: DARTS128 and DARTS256; DARTS512 packs low bits with a byte map and is not affected
Discovery: Moderate
Exploitation: Adding a constant to an eligible packed field of a valid signature gives a different byte string that verifies for the same message; no signing key or new message is involved
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
The signature packs the low bits of the response in blocks of eight base-17 digits. `poly_unpack_lowbits` reads each fixed-width field, peels off eight digits and discards the remaining quotient without checking that it is zero (`poly.c:746–790` for DARTS128; the DARTS256 branch follows). The field is wider than eight base-17 digits need, so a field value `v` and `v + 17^8` decode to the same digits whenever the sum still fits.

On one honest DARTS128 signature, 45 of the 128 blocks were eligible, and adding 17^8 to any one of them gave a byte-distinct signature that the submitted verifier accepted for the same message. A changed message was rejected. The specification adds a strong-unforgeability property (§3.3.3), which a second valid encoding of the same signature contradicts.

### Reproducing

```sh
sed -n '746,790p' sign-08/Implementations/Reference_Implementation/DARTS128/poly.c
```

This is a source witness: the decoder has no range check on the discarded quotient. The accepted aliases were observed with a driver against the archived code and are not part of the witness.

## sign-08-7: A 32-bit sum wraps and disables the key-generation norm check at DARTS256 and DARTS512

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: DARTS256 and DARTS512 in all fifteen trees by source (the witness runs the reference); DARTS128 values stay below 2^31
Discovery: Moderate
Exploitation: Key generation returns keys that the specification rejects (24 of 100 at DARTS256 and 62 of 100 at DARTS512 in the run); the bound on ‖cs‖ that the check guarantees no longer holds for them; no signature leakage shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; key-generation consequence by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/RNPHVDLQBPYLSORO3BAL44W4ZCTBINKQ/)
Follow-up source: [DARTS team's 2026-11-22 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JBVT46XZ2ZQ2XVNR4UQJGRNQTAZ2Z5H7/)

Key generation resamples the secret until `N(s) ≤ γ²n` (Algorithm 6 line 6, physical p. 8); the specification states that only then is `‖cs‖ ≤ γ√τ` guaranteed for every challenge, and sets γ so that about half of all secrets are rejected. `polyveckl_sqsing_value` returns an `int64_t` but accumulates the sum in `int32_t res` (`polyvec.c:652`), and `sign.c:70` compares the result with the bound. At DARTS256 and DARTS512 the true value often exceeds 2^31, the sum wraps, and the wrapped value passes the test.

For 100 reference keys per set, N(s) recomputed from the unpacked secret in 64-bit arithmetic exceeded the bound for 24 keys at DARTS256 and 62 at DARTS512, while the code's value was below the bound for every key; at DARTS128 no key exceeded it. The results are the same with GCC at `-O0` and `-O3` and with Clang at `-O2`. The sum should be kept in 64 bits.

### Proposed fixes

In a [2026-11-22 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JBVT46XZ2ZQ2XVNR4UQJGRNQTAZ2Z5H7/) to the original post, the DARTS team says the reported issues are addressed in the reference and AVX2 implementations published at `github.com/MathEternal/DARTS-NGCC`, with the documentation under revision. This records the response; the revised code was not evaluated.

### Reproducing

```sh
sh sign-08/reproduce_pk_reads.sh
```

The witness unpacks each generated secret key and recomputes N(s) with 64-bit integers.

## sign-08-8: Verification ignores the public-key length, and AVX2 verification reads past a correctly sized key

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine `sig_verify` wrappers for the length; the six AVX2 trees for the over-read
Discovery: Trivial
Exploitation: Out-of-bounds read of a caller-supplied short public key, and in AVX2 builds a 14- or 15-byte read past every exactly sized public key, which faults when the key ends at a page boundary; no disclosure shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/RNPHVDLQBPYLSORO3BAL44W4ZCTBINKQ/)
Follow-up source: [DARTS team's 2026-11-22 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JBVT46XZ2ZQ2XVNR4UQJGRNQTAZ2Z5H7/)

`sig_verify` discards `pk_len_bytes`, and `unpack_pk` reads the fixed-size key: a valid public key in a heap buffer one byte short, declared at that length, is read past its end (`packing.c:46`) under AddressSanitizer at all three sets, while the full-length buffer is clean. Separately, the AVX2 `poly_q_unpack` loads 32 bytes for every 17 (DARTS128 and DARTS256) or 18 (DARTS512) it consumes, so AVX2 verification reads 15 or 14 bytes past an exactly sized public key. Built with the candidate's flags, verification faults when the key ends at an inaccessible page and succeeds with that much slack or a readable page.

### Proposed fixes

In a [2026-11-22 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JBVT46XZ2ZQ2XVNR4UQJGRNQTAZ2Z5H7/) to the original post, the DARTS team says the reported issues are addressed in the reference and AVX2 implementations published at `github.com/MathEternal/DARTS-NGCC`, with the documentation under revision. This records the response; the revised code was not evaluated.

### Reproducing

```sh
sh sign-08/reproduce_pk_reads.sh
```
