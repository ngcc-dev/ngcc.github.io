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
Follow-up source: [Martin Feussner's independent DARTS-128 recovery](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/J7RWJSD6H5IBCXDBD2XSHKCKGARBT6TA/) and [the DARTS team's confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3XGOCUUIBO5UJ5C4GQKIIWR3AHAQNI2X/)

Step 9 of Algorithm 7 accepts every signing attempt when the hidden branch bit is `b=1`, but for `b=0` accepts only when `Comp_d(omega) = Comp_d(omega+c alpha)`. Because `omega=A round(y)`, this asymmetric restart tilts the joint distribution of the published challenge and rounded response by a small key-dependent multiple of the sparse secret. Shi separates that impulse train from a smooth fixed bias, then enumerates the few uncertain coefficients and checks candidates with the exact public relation `e=(q+1)/2 beta-A s mod q`, requiring ternary `e`.

We replayed the pinned PoC's accumulators from 20,000,000 DARTS-128 signatures. The collector derives them only from decoded public signature fields. The full data estimated 19,983,582 samples, measured a `656.87`-sigma signal, and recovered all secret polynomials after 40,342 public-relation candidates. The recovered bytes before the independent signing seed matched the submitted secret-key control exactly. Setting that irrelevant seed to zero still produced a fresh-message signature accepted by the untouched submitted verifier; changing one message byte was rejected. This is therefore equivalent signing-key recovery and an EUF-CMA forgery, not merely a distinguisher.

Feussner independently reports full DARTS-128 recovery and fresh-message forgery from 17,000,000 signatures using negacyclic normal equations, ternary classification, and Kannan/BKZ completion. The DARTS team confirms that both attacks exploit the same omitted factor `2` in Step 9.

### Proposed fixes

The [DARTS team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3XGOCUUIBO5UJ5C4GQKIIWR3AHAQNI2X/) proposes replacing the submitted `(1-b)c*alpha` comparison term by `(1-2b)c*alpha`. This section records the proposal without evaluating it.

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

The reference `poly_uniform` initially squeezes nine blocks and retains leftovers using `% 16` (`poly.c:917–945`). AVX2 initially squeezes seven blocks, then uses `% Q_BITS` in its scalar path and a separate four-way refill path (`poly.c:1266–1355`). These differences are consistent with divergent `ExpandA` matrices: the first-record public keys in the submitted reference and AVX2 KATs share their seedA prefix and diverge immediately afterward at all three tiers. The forum reports mutual rejection of honest cross-implementation signatures at all three tiers, 4/4 seeds, while each build verifies its own signatures. Our certificate confirms the divergent source paths, not that runtime experiment. The specification does not fix the `PolyUniform` squeeze schedule, so this is an implementation interoperability finding, not a design or forgery claim.

### Proposed fixes

The forum reports that changing AVX2's expansion read pattern restores reference-KAT verification. This proposal is recorded without evaluating it.

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
