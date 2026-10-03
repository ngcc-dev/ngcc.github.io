<!-- synchronized report: sign-20/report.md -->
Candidate: Qing Luan
Family: Code-based (restricted syndrome decoding, MPC-in-the-head)
Archive: [QingLuan.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QingLuan.zip) (SHA-256: `2eb8f3ed205eb7c7e8b3108a997b59643d1aa5579035b8093b4ddbe051a48007`)

Evaluation scope: Qing Luan instantiates the CROSS-RSDP protocol but fixes its
multi-pipe hash, counter-mode XOF and Hash-DRBG as concrete SM3-based
constructions rather than ICCS placeholder functions. These symmetric
constructions are therefore part of the submitted design and require evaluation
alongside the public-key protocol; replacing them would evaluate a revised
instantiation.

## sign-20-1: Qingluan-128's own quantum accounting falls below the 80-bit target

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Qingluan-128 specification and parameter set
Discovery: Trivial
Exploitation: The specification's halved-exponent rule gives 64.4 and 71.5 quantum-cost bits; no end-to-end quantum gate cost is established
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QMVN4EMKVLFXOLVNGTSR7KAR4J4OKDFE/)

The NGCC [Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf) set an 80-bit quantum-security floor for the 128-bit classical tier. Qingluan §3.2.4 instead applies its rule `quantum = classical/2` to a 128.8-bit Fiat–Shamir forgery estimate and a 143-bit key-recovery estimate. This gives cost exponents 64.4 and 71.5 respectively; the latter is a halved ISD exponent, not a count of identical Grover iterations. The specification's own table consequently prints 64-bit binding security next to an `>= 80 bit` target, while describing the shortfall as “NIST category 1” under bounded-depth Grover rather than literal `2^80` work.

This is a contradiction in the claimed parameter accounting, not a demonstrated quantum forgery. The call's 80-bit target cannot be interpreted as a bare Grover-iteration threshold: that convention would assign AES-128 only `2^64` iterations. Reversible SM3, syndrome decoding, memory, depth, and parallelization costs could readily close the reported 8.5–15.6-bit gaps, and no circuit-level estimate is supplied. Under the classification policy this is therefore a Medium proof gap. Changing only the Fiat–Shamir round parameters does not resolve the inconsistency in the specification's own model because the fixed `(n,k)=(127,76)` key-recovery exponent remains 71.5.

The other three parameter sets are not affected by this numerical inconsistency: under the same convention their stated quantum estimates remain slightly above their 128-, 192-, and 256-bit targets.

### Reproducing

```sh
python3 sign-20/reproduce_quantum_accounting.py
```

The witness extracts the relevant statements and numbers from the submitted PDF, recomputes `128.8/2 = 64.4` and `143/2 = 71.5`, and checks that both fall below the specification's own 80-bit row. It does not simulate a quantum circuit or claim an executed attack.

## sign-20-2: DRBG rollback is outside the security model, so the reported witness recovery is not an attack

Severity: Info
Status: Confirmed
Layer: Design
Affected: All four Qing Luan parameter sets, only if the signer's DRBG is rewound to an earlier internal state
Discovery: Moderate
Exploitation: None within the security model; the reported recovery requires rewinding the signer's DRBG
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-02
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/OBQXT2H5IIQPMNT6TQFP3OHJNBDBJKQD/)

The post rewinds the signer's DRBG to the same internal state before two signatures on different messages. The round seeds then repeat while the Fiat–Shamir challenges differ: a type-1 opening in one signature reveals a round seed and hence `eta'_i`, a type-0 opening in the other reveals `v_i = eta - eta'_i mod 7`, and combining them recovers the long-term exponent witness. We reproduced the extraction and a fresh-message forgery, with fresh-state, wrong-key, wrong-message and corruption controls, at all four levels.

This is recorded for information and is not a vulnerability. The evaluation's randomized-signature model supplies fresh coins; it does not give the adversary access to seed, clone, reset or rewind the generator's internal state. Qing Luan's only per-signature freshness is the DRBG output, so rolling the DRBG back repeats it; signing that binds its per-signature seed to the secret key and message, as hedged or deterministic signing does, would tolerate such repetition. Ordinary signing with a correctly operating random bit generator is unaffected.

The specification's §3.3.4 (physical p. 17) discusses DRBG reset under "Temporary Key Reuse". It concedes that a reset across two different messages repeats the round seeds while the challenges differ, yet concludes that Qing Luan "demonstrates strong robustness under DRBG temporary-state reuse". The reproduced witness refutes that informal robustness conclusion. It does not break Qing Luan's stated EUF-CMA model (§3.1.1, p. 13), and the submission states no formal security property under DRBG rollback.

### Reproducing

```sh
sign-20/reproduce_rollback.sh
```

The wrapper downloads a hash-pinned artifact and requires every level and control to pass.

## sign-20-3: Nested SM3 multicollisions give sub-target message binding for QingLuan-384 and -512

Severity: Critical
Status: Confirmed
Layer: Design
Affected: QingLuan-256 security analysis; below-target forgery bounds for QingLuan-384 and QingLuan-512
Discovery: Moderate
Exploitation: One signing query; a fixed-prefix second preimage costs about 2^256 times a polynomial in the pipe count and transfers the signature to a fresh message
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-03
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4GD326C4OBZ6TEJQCSJ3QSCI3QBNTYGV/)

Qing Luan concatenates `P` domain-separated SM3 pipes and claims full `2^(256P)` (second-)preimage and target-collision resistance (§§1.5.2, 2.4.1 and Theorem 1). Joux's recursive multicollision construction finds preimages of a concatenation of any fixed number of Merkle–Damgård pipes in about `2^256` times a polynomial in 256 and `P`, rather than exponential work per pipe. The signature's revealed salt is a fixed prefix for this single-target construction, not a barrier.

The standard accounting is `poly(256^P) 2^256`; one published refinement gives a leading factor `256^(P-2)/2^(P-4)`, about `2^258`, `2^265` and `2^272` for two, three and four pipes. A second preimage for the fixed `salt || message` digest transfers an observed signature to a fresh message. Thus the 384- and 512-bit sets miss their required targets; the 256-bit set is not claimed below target under this accounting. The scaled witness demonstrates the basic two-pipe construction and a less efficient direct extension; the decisive higher-pipe bound is a literature-backed analytic certificate, not a full-size computation.

References: [Joux, CRYPTO 2004, §§4.2–4.3 and Appendix A](https://www.iacr.org/archive/crypto2004/31520306/multicollisions.pdf); [Bernstein et al., *How Risky is the Random-Oracle Model?*, §2.2](https://eprint.iacr.org/2008/441)

### Reproducing

```sh
QING_KEYS=1000 sign-20/reproduce_qing_hash_sampler.sh
```

## sign-20-4: Signing re-expands the secret through a variable-work sampler

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: All four reference implementations
Discovery: Trivial
Exploitation: Repeatable secret-seed-dependent execution trace; no witness or key recovery demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-03
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4GD326C4OBZ6TEJQCSJ3QSCI3QBNTYGV/)

Every signature re-expands the persistent secret seed through `rsdp_csprng_fz` (`sign.c:54–57`; `rsdp.c:68–76`). That sampler squeezes bytes until the masked value is not seven. Its draw count is therefore a repeatable function of the secret seed, contrary to §1.7's constant-time description.

Instrumentation that changes no sampler decision finds variable but exactly repeatable counts at all four levels. The trace's marginal entropy is about 4.2–5.2 bits under an ideal-XOF model. Xiong and Wang report no significant correlation with the accepted secret coefficients; our witness does not test that negative result. This is not a demonstrated conditional leak beyond the public key, and no recovery path is known.

Constant-time fix (easy, hence Low): pre-squeeze a bounded oversized buffer and masked-compact the non-seven candidates, with a public failure/retry bound.

### Reproducing

Run the same wrapper as above. It checks both the scaled hash construction and the submitted-source sampler with controls.

## sign-20-5: Qing Luan's random-generation state caps the 384- and 512-bit sets at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Specified/standalone QingLuan-384 and QingLuan-512 key generation; QingLuan-512 counter-XOF in both core paths
Discovery: Moderate
Exploitation: At most 2^256 trials to enumerate a key-generation root or equivalent level-512 witness
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-02
Additional reference: [Feussner's pinned Qing Luan artifact](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/91f2ddf0590a24ad39afc2ce2ee4f2627ec54726/Qing-Luan)

The specification fixes the SM3 Hash-DRBG seed at 32 bytes (§1.5.4). In the standalone implementation, the 32-byte `V` determines `C`, the counter starts fixed, and the entire output schedule has at most `2^256` roots (`utils.c:28,45–46,83–88`). Enumerating those roots and comparing the public key recovers the corresponding signing seed, below the 384- and 512-bit claims. The API KAT adapter uses a different 55-byte state and is not covered by this first argument.

Independently, QingLuan-512's counter-XOF evaluates `SM3(K || BE32(i))` with a 128-byte, block-aligned `K` (`hash.c:348–371`). One 256-bit SM3 chaining state after the two key blocks determines every output. The public `Seed_pk` blocks test a guessed state; a match reconstructs the preceding secret `Seed_e` blocks and an equivalent signing witness. The 96-byte QingLuan-384 key is not block-aligned, so this second argument does not apply there.

### Reproducing

```sh
python3 sign-20/reproduce_state_ceiling.py
sign-20/reproduce_rollback.sh
```

The static certificate checks the DRBG and XOF dimensions. The hash-pinned replay independently implements SM3 compression and reconstructs eight level-512 output blocks from one post-key state.
