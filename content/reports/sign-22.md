<!-- synchronized report: sign-22/report.md -->
Candidate: Rhyme
Family: Lattice-based
Archive: [Rhyme.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Rhyme.zip) (SHA-256: `7b509d21c6674bc23751b8743cb7c2a4a07ee295fafe04e2fa95c0613160bdfd`)

## sign-22-1: The implemented message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Rhyme-SHAKE-384/-512 and Rhyme-SM3-384/-512 reference and optimized implementations; specification leaves the hash length undefined
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Rhyme uses the unsalted message binding `mu = H_gen(pk, M)`. The SHAKE and SM3 implementations for the 384- and 512-bit sets all fix `mu` at 64 bytes, enabling a generic collision-and-signature-transfer attack in about `2^256` evaluations, below each set's claim.

The PDF specifies the construction but never defines the output length of `H_gen`. The implementation ceiling is confirmed, but the omission prevents calling the 64-byte length a clean normative parameter.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-22-1
```

The `sign-22-1` check verifies the normative message-binding algorithm on
physical PDF pages 29–32 and 50–51 and the source digest constant.

## sign-22-2: The implementation expands the complete key pair from a 256-bit root

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Rhyme-SHAKE-384/-512 and Rhyme-SM3-384/-512 reference and optimized implementations; specification leaves the root length undefined
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The affected Rhyme-384 and Rhyme-512 implementations expand each entire key pair from one 32-byte root. The generated public-key support is therefore at most `2^256`; generic root enumeration and public-key matching recovers the corresponding signing key.

The normative algorithm denotes the root length by `rho_0` but never assigns `rho_0` in its parameter table. This is both an implementation security ceiling and a specification omission.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-22-2
```

The `sign-22-2` check verifies the normative KeyGen algorithm on physical PDF
pages 29 and 50–51 and the source root constant.

## sign-22-3: Rhyme-SM3 omits the specified doubled-width parity mask

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized Rhyme-SM3-128, -256, -384, and -512; the SHAKE implementations are controls
Discovery: Moderate
Exploitation: Valid signatures give noisy linear equations in the secret parity; key recovery or forgery not demonstrated
Credit: Yijian Liu, with AI assistance
Date: 2026-09-28
Original source: [Liu's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/32MEEUHEHAW2TQD74RYHELHXNBUJKU5I/)

Algorithm 6 samples `X'` from `D_Z,sigma` but requires the independent masking noise `e_bottom` to come from `D_Z,2sigma`. Theorem 4.3 says that the doubled width is essential to make its parity statistically close to uniform and uses an identical `D_Z,2sigma` sample in the simulator. Every submitted SM3 signer instead calls the ordinary `SampleGauss` for both values (`src/sign.c:333–334`); that function always uses the `rhyme_cdt_g` table (`src/sampler.c:175–181`). Both the reference and optimized trees are affected. The SHAKE trees contain the missing separate `SampleGaussE`/`rhyme_cdt_e` path and provide a direct control.

Reducing a valid signature modulo two removes the `2 B' X'` term. The rejection sampler's offset has the challenge's parity, so the remaining public relation is

`z_bottom mod 2 = s_tail * c + e_bottom mod 2`.

Exact evaluation of the submitted CDT gives `E[(-1)^e]` equal to `6.3322e-4`, `4.8828e-4`, `4.1941e-4`, and `3.7652e-4` for the four SM3 levels. Thus signatures carry secret-dependent noisy parity equations, and Theorem 4.3's parity-masking argument and stated `2sigma` condition—and the later bounds that invoke them—do not apply to the submitted SM3 implementations. This report does not claim an efficient decoder for those equations, a signing-key recovery, or a forgery; that boundary keeps the finding at Medium.

Use the specified doubled-width sampler/table for `e_bottom`, retaining the already distinct nonce/domain used by the SM3 signer, and re-evaluate the complete transcript distribution. The submitted SHAKE implementation provides a working model for the separate sampler.

### Reproducing

```sh
python3 sign-22/reproduce_sm3_parity_bias.py
```

The script checks both implementation trees, confirms the SHAKE control, and computes the four exact CDT parity biases.

An optional accepted-transcript experiment generates and verifies 25,000 deterministic Rhyme-SM3-128 signatures, then scores the predicted parity relation over 25.6 million bottom-response coefficients:

```sh
sh sign-22/reproduce_sm3_parity_runtime.sh
```

The checked run measured bias `7.025e-4`, versus the exact raw-CDT value `6.3322e-4`; a zero-vector wrong predictor measured `-1.028125e-4`. It takes about two minutes on this host.

## sign-22-4: An undersized rejection envelope permits practical secret-tail recovery and forgery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: A deterministic Rhyme-SHAKE-128 completion using the specification's stated closed-form boundary and a central-first fixed order; the submitted SHAKE signer is excluded
Discovery: Hard
Exploitation: At most 40,000 chosen-message signatures, followed by seconds of regression
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-01
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3FOEXR4RO5COXIJ7RQZH2GSXCTAH7V3R/) and [pinned public analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/83360df0c060f54c327754a7baa3d7be10acfeeb/Rhyme)

Appendix A (physical pp. 63–64) first states the correct cumulative-envelope condition for Rhyme's sequential rejection sampler, but then derives a boundary expression and expressly calls that closed form a valid upper bound. It is not: for Rhyme-128 the formula gives about `10^-5`, while the preceding condition needs about `1.002`. Algorithm 3 also requires a fixed enumeration order without defining it. Using that specification-sanctioned closed form with a deterministic central-first order makes the sampler strongly order-dependent: the sampled offset is usually close to the negative public challenge, so each signature exposes a noisy linear equation in the four-polynomial secret tail.

Negacyclic least-squares regression recovers all 1,024 tail coefficients from at most 40,000 chosen-message signatures. The recovered public relation then gives a zero-commitment signature on a fresh message, accepted by the pristine submitted verifier. Our deterministic replay used a fixed key tag and preset checkpoints: all 50,000 generated signatures passed the pristine verifier and decoder, exact recovery held at the preset 30,000-signature checkpoint, the fresh-message forgery was accepted, and wrong-message, perturbed-tail, and wrong-key controls were rejected. The attack harness patches `encoding.c` in its scratch signer to restart the roughly 10% of signing attempts whose encodings do not fit; the verifier used for the forgery remains pristine.

This is a break of a deterministic implementation permitted by one of the submitted specification's conflicting prescriptions, not of the pristine submitted signer. Critical severity rests on the specification explicitly presenting the vulnerable closed form as a valid upper bound; the earlier cumulative condition points to the safe choice instead. The submitted SHAKE source uses ascending arrays and `M = 1.002214572...`, which satisfies the required envelope for its operational CDT distribution; the same-key safe-envelope control does not recover the tail or forge.

### Proposed fixes

The cited analysis proposes replacing the boundary expression by the exact cumulative-ratio maximum or a proved upper bound, testing the resulting cumulative mass, and specifying a canonical enumeration order and one Gaussian convention. This section records those proposals without evaluating them.

### Reproducing

```sh
sh sign-22/reproduce_order_dependent_forgery.sh
```

The default replay checks the envelope calculation, the frozen public evidence, the recovered public relation, the accepted forgery, and three negative controls. Set `FULL=1` to generate 50,000 chosen-message signatures and repeat the complete recovery; NumPy is required and the regression uses about 2.5 GiB of memory.

## sign-22-5: A valid-bound response can overrun Rhyme-512's encoder table

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference Rhyme-SHAKE-512 signing
Discovery: Moderate
Exploitation: A valid-bound response causes an AddressSanitizer out-of-bounds read; no crash, forgery or secret disclosure was independently demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/J3PZL7SVYFLYJZ75Q5S5Y3ALIC65E5GZ/)

For the escape-less `z1` row, `encode_z` indexes `es1[hi]` without checking `hi` (`src/encoding.c:130–142`). At this level `B0=916`, `RANS_L1=4`, and `RANS_NZ1=113`. Every coefficient from 892 through 916 is within the allowed bound yet gives `hi≥113`, beyond the 113-entry table. Our native AddressSanitizer test with `z1[0]=916` reaches a global-buffer-overflow read; the `z1[0]=0` control encodes normally. The post reports 10 crashes in 100 honest signing attempts, a frequency we have not repeated. This is an availability and memory-safety defect, not a signature forgery.

### Reproducing

```sh
sh sign-22/reproduce_encoder_bound.sh
```

The wrapper builds the submitted encoder with AddressSanitizer, tests the boundary coefficient and the control, and leaves build products in a temporary directory.

## sign-22-6: Long messages share an all-zero representative in Rhyme-SM3

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Rhyme-SM3-128, -256, -384 and -512 reference and optimized implementations
Discovery: Trivial
Exploitation: One signature on a message longer than the XOF input limit verifies for a different long message without further signing queries
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

Rhyme hashes `pk || M` to form its message representative (`src/sign.c:311–314,508–511`). Its SM3 XOF instead holds at most 8,192 input bytes; exceeding that limit sets an overflow flag and makes every subsequent squeeze return zero (`sm3_xof.c:42–48,115–119`). Thus every message with `|pk|+|M| > 8192` has the same representative under a fixed key. The same source behavior appears in all four SM3 levels and both submitted implementation families.

An independently rebuilt reference signer at levels 128 and 512 accepted one signature for two different long messages, including a 20,000-byte message. Signatures and messages at the exact non-overflow boundary supplied rejection controls. This is a practical fresh-message EUF-CMA forgery, not a hash-collision cost estimate. The XOF must process the complete input or reject unsupported message lengths before signing and verification.

### Reproducing

```sh
sh sign-22/reproduce_long_message.sh
```

The wrapper builds the submitted reference 128- and 512-bit signers in temporary directories and checks accepted long-message transfers and the boundary controls. It does not test the optimized binaries, whose input-limit and zero-output logic was checked in source.

## sign-22-7: The specified Gaussian width makes the proof vacuous within the required query budgets

Severity: High
Status: Proof gap
Layer: Design
Affected: Rhyme-128, -256, -384 and -512, SHAKE and SM3 profiles, reference and optimized implementations
Discovery: Moderate
Exploitation: None; the stated EUF-CMA and sEU-CMA bounds stop covering signing after about 2^32 to 2^34 queries, and no key recovery or forgery follows
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Theorem 4.3 (physical p. 41) proves statistical HVZK with simulation error `eps_zk = 4 eps + O(eps^2)` under the condition `sigma >= eta_eps(Z^{nD})`. Corollary 4 (EUF-CMA, p. 44), Corollary 5 (sEU-CMA, p. 45) and both parts of Theorem 4.6 (p. 46) then multiply the no-message or SIS/GA-MLWE advantage by `(1 + 4 eps)^{Q_S}`. The specification never states `eps`, but it follows from its own definitions. Section 2.7 (p. 11) uses `rho_s(x) = exp(-pi x^2 / s^2)`, and `Z^k` is self-dual, so the smallest `eps` with `eta_eps(Z^k) <= s` is exactly `theta(s)^k - 1`, where `theta(s) = sum_j exp(-pi s^2 j^2)`. Table 3 (p. 53) gives `sigma/sqrt(2 pi)` = 1.295870, 1.316036, 1.326374 and 1.335898, and the submitted `rhyme_cdt_g` tables realise exactly these standard deviations (`include/params_tables.h`, all SHAKE trees).

With `k = nD` = 2,560, 5,120, 7,168 and 10,240, this gives `eps` = `2^-35.50`, `2^-36.00`, `2^-36.29` and `2^-36.50`; Lemma 2.2's upper bound gives the same values. The multiplier therefore exceeds 2 once `Q_S` passes `2^33.0` to `2^34.0`, and its natural logarithm is about `7.6e8` to `1.5e9` at the required `2^64` messages per key and `5e13` to `1e14` at the `2^80` evaluation ceiling. At those budgets the bounds are vacuous: the multiplier alone is far larger than `2^lambda`, so they say nothing about forgery probability. The SM3 trees ship narrower widths that are not in Table 3 (`sigma_base` = 1.277834, 1.298280, 1.310093 and 1.318410). They give `eps` = `2^-34.2` to `2^-35.2`, and coverage ends at `2^31.6` to `2^32.7` queries.

This loss comes from Rhyme's chosen width, not from a generic reduction term. A width with `eps <= 2^-80` (for Rhyme-128, `sigma_base` about 1.80) would keep the multiplier below `1.0001` at `2^64` queries. The deviation the theorem bounds is real: the parity of the `D_{Z,2sigma}` masking noise has an exact per-coefficient bias of about `10^-15`. Its Kullback-Leibler divergence, however, is only about `2^-85` per signature, so even `2^80` signatures carry far less than one bit about the secret. A Rényi or KL argument could therefore plausibly restore a meaningful bound, but the submission contains none. The High rating records that the submitted security theorems cover fewer signing queries than the required per-key lifetime; no attack is claimed.

### Reproducing

```sh
python3 sign-22/certify_smoothing_budget.py
```

The certificate checks all 16 `params_tables.h` copies against Table 3, confirms that each `X'` CDT has the stated standard deviation, evaluates `eps` and the `(1+4eps)^{Q_S}` multiplier at `2^34`, `2^64` and `2^80` queries, and checks the theorem wording in the PDF when `pdftotext` is installed. As controls, it requires the exact `eps` not to exceed the Lemma 2.2 bound and requires an `eps <= 2^-80` width to keep the multiplier below 2 at `2^64` queries. It runs in under a second and makes no statistical measurement of signatures.

## sign-22-8: Rhyme-SM3 uses smaller challenge weights than specified, leaving every challenge space below its level

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Rhyme-SM3-128, -256, -384 and -512; reference and optimized implementations; Rhyme-SHAKE uses the specified weights
Discovery: Trivial
Exploitation: Generic challenge-guessing forgery from the public key costs about 2^108.1, 2^212.5, 2^308.4 and 2^425.0 trials; executed end to end at a toy weight
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AMCVNVCBAMYAOWTK23BPEA5Y45V4GRA2/)

The specification uses binary challenges, `c_i ∈ {0,1}` of weight τ, so the challenge space has `binomial(n,τ)` elements (physical p. 18), and its single parameter table gives τ = 30, 58, 113 and 115 (Table 3, p. 53). The security proofs carry a `1/|C|` term (Theorem 4.2, p. 38; Corollary 2, p. 40; Theorem 4.6, p. 46). All sixteen trees share one binary `SampleChallenge` (`src/sampler.c:195–220`) that sets τ positions to 1, and the verifier recomputes `c` from the transmitted `c_tilde` with it (`sign.c:514`). Rhyme-SHAKE sets `RHYME_TAU` to the Table 3 values, but all eight Rhyme-SM3 trees set 23, 44, 77 and 87 (`include/params_tables.h:18,177,386,600`). These are the smallest weights with `log2 binomial(n,τ) + τ ≥ λ`, the sizing for signed challenges, and give challenge spaces of 2^108.08, 2^212.46, 2^308.40 and 2^425.00. The archive's own history shows the SHAKE tables raised from these values in its final commit while the SM3 tables were left unchanged, and the submitted Rhyme-SM3 KAT signatures have binary challenges of exactly these weights.

Verification accepts `(c_tilde, z)` when `z` meets the norm bounds and `H(w, µ) = c_tilde` with `w = A·z − q·j·c mod 2q` (`sign.c:517–527`). A forger fixes `z` within the bounds and a target `c*`, computes `w*` from the public key, and hashes fresh messages until `SampleChallenge(H(w*, µ)) = c*`. Each trial succeeds with probability `1/binomial(n,τ)` and costs two hash calls and one sampler call.

A copy of the reference Rhyme-SM3-128 sources with only `RHYME_TAU` changed to 2 (2^14.99 challenges) gave a forgery after 35,367 trials without the signing key; the unmodified verifier accepted it and rejected it for another message. Weight 3 (2^21.40) took 3,450,601 trials.

### Reproducing

```sh
sh sign-22/reproduce_challenge_space.sh
```

The witness checks the sampler and τ in all sixteen trees, requires 20,000 sampled challenges per tree to be binary of weight exactly τ, and runs the toy forgery with an unmodified τ = 23 control.

## sign-22-9: Verification ignores the public-key length and over-reads a short key

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rhyme-SM3 and Rhyme-SHAKE at all four levels; reference and optimized implementations
Discovery: Trivial
Exploitation: A caller-supplied public key shorter than its declared length is read out of bounds; no disclosure shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AMCVNVCBAMYAOWTK23BPEA5Y45V4GRA2/)

`sig_verify` discards `pk_len_bytes` (`SIG_AlgorithmInstance.c:62`, identical in all sixteen trees). Once the signature decodes and passes the norm checks (`sign.c:491–502`), `crypto_sign_verify` unpacks the public key (`:504`), copying 32 bytes (`packing.c:40`) and bit-reading the rest of `CRYPTO_PUBLICKEYBYTES` (`:44`), and later absorbs the full length again (`sign.c:509`). Under AddressSanitizer, with a well-formed signature that needs no key, a 16-byte heap public key gave a 32-byte read past its end at `packing.c:40`, and a key one byte short gave a heap-buffer-overflow at `packing.c:44`, in every tree. Full-length keys ran cleanly. Callers that pass complete keys are unaffected.

### Reproducing

```sh
sh sign-22/reproduce_short_pk.sh
```

## sign-22-10: Rhyme-SM3 leaks its XOF buffers on every verification

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rhyme-SM3-128, -256, -384 and -512; reference and optimized implementations (same XOF state handling by source; the witness runs the reference); Rhyme-SHAKE is not affected
Discovery: Trivial
Exploitation: Unbounded memory growth in a long-running verifier; no disclosure or corruption
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19

The SM3 backend maps the streaming `rhyme_shake256_*` and `rhyme_shake128_*` calls onto `sm3_xof` states (`rhyme_xof.c:8–21`), whose squeeze grows a cache with `realloc` (`sm3_xof.c:77`). The streaming interface has no release call, and only the one-shot helper clears its state (`sm3_xof.c:175`), so every streaming XOF instance loses its cache. Under LeakSanitizer one verification leaked 2,944, 7,712, 14,272 and 15,488 bytes in 7 to 12 blocks at the four levels; the Rhyme-SHAKE builds leaked nothing. Signing uses the same wrappers but was not measured.

### Reproducing

```sh
sh sign-22/reproduce_verify_leak.sh
```
