<!-- synchronized report: sign-17/report.md -->
Candidate: OPS Digital Signature Algorithm
Family: Lattice-based signature
Archive: [OPS Digital Signature Algorithm.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/OPS%20Digital%20Signature%20Algorithm.zip) (SHA-256: `02322c6792259231ab8eb3cc094be32be02a1b9b6b1d7c86b0029c37b0f04d09`)

## sign-17-1: The specified fixed-support challenge permits public-key forgeries in 2^39, 2^45, and 2^90

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Written OPS-SIG specification, all three parameter sets; submitted reference and AVX2 implementations are unaffected
Discovery: Moderate
Exploitation: Public-key-only forgery in about 2^39, 2^45, or 2^90 trials; no signing query
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/P72SIPCDX7C2TRO36VBHX7GGMKGDNCIH/)
Follow-up source: [OPS team's PKC Forum acknowledgment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TAVWDZWBTG3FSHKDHATS5YNKNT7JN5X4/)

Algorithm 6 (physical page 9) swaps `idx[i]` and `idx[j]`, then writes the new sign to `c[idx[j]]`. At step `i = n-tau+t`, the old `idx[i]` has not previously moved, so after the swap `idx[j] = i`. Every challenge therefore has the fixed public support `{n-tau,...,n-1}`; only its `tau` signs vary. The challenge spaces have just `2^39`, `2^45`, and `2^90` elements, rather than the intended signed-weight spaces.

This enables a public-key-only forgery. Choose a short response and a target challenge on the fixed support, reconstruct the verifier's commitment from the public key, and grind the hint until the hash maps back to that challenge. The resulting costs are below the claimed 128-, 256-, and 512-bit levels, so the specified scheme violates its SUF-CMA and the required EUF-CMA targets. A reduced-`tau` end-to-end witness forges fresh messages for all three parameter geometries; changed-message and submitted-sampler controls reject. At the real parameters, direct enumeration gives the bounds above without requiring the full searches to be run.

The submitted `poly_challenge` uses the correct ML-DSA-style `c[i] = c[j]; c[j] = sign` update and reaches all coefficient positions. The finding is therefore confined to an implementation faithful to the written Algorithm 6, not the submitted binaries.

### Proposed fixes

The original post proposes replacing Algorithm 6 with the SampleInBall procedure already used by the submitted implementation. This section records the proposal without evaluating it.

The [team's 2026-10-09 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KGQ6LJVGF35SHMFQ5EPJ5AH4UYHAHAG3/) says specification v2.0 now uses `c[i]=c[j]; c[j]=sign` and makes parsing and refill rules explicit. This is recorded without evaluating the revision.

### Reproducing

```sh
make -C sign-17 reproduce-spec-findings
```

The pinned wrapper checks the real-parameter support collapse, runs reduced-`tau` public-key-only forgeries at all three geometries, and requires both changed-message and submitted-sampler rejection controls. It prints `ATTACK sign-17-1 ... CONFIRMED`.

## sign-17-2: The specified high-bit wrap rejects honest signatures

Severity: Low
Status: Confirmed
Layer: Design
Affected: Written OPS-SIG specification, all three parameter sets; submitted reference and AVX2 implementations are unaffected
Discovery: Moderate
Exploitation: Honest signatures fail verification; no forgery or key recovery
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/P72SIPCDX7C2TRO36VBHX7GGMKGDNCIH/)
Follow-up source: [OPS team's PKC Forum acknowledgment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TAVWDZWBTG3FSHKDHATS5YNKNT7JN5X4/)

Algorithms 30 and 32 (physical pages 14–15) use `ceil(q/alpha)` as the high-bit bucket count, where `alpha = 2*gamma2`. For every submitted set, `alpha` divides `q-1`, so the reachable count is `(q-1)/alpha`; the specified ceiling is one larger. The top bucket is consequently not folded to zero at the wrap boundary, and a verifier following the specification can reconstruct different high bits from the signer.

In 2,000 honest signatures per set, a verifier using the specified operations rejected 149 (7.45%), 630 (31.50%), and 1,339 (66.95%) at the 128-, 256-, and 512-bit sets. The submitted rounding code, which uses `(q-1)/alpha`, rejected 0 of 2,000 in each control. This is a specification correctness and interoperability defect, not an attack on the submitted code.

### Proposed fixes

The original post proposes using `m = (q-1)/(2*gamma2)` in Algorithms 30 and 32, matching the submitted implementation. This section records the proposal without evaluating it.

The [team says](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KGQ6LJVGF35SHMFQ5EPJ5AH4UYHAHAG3/) specification v2.0 also revises tie rounding and encoding widths to match the code. This is recorded without evaluating the revision.

### Reproducing

```sh
make -C sign-17 reproduce-spec-findings
```

The wrapper transcribes the specified rounding into the otherwise submitted verifier, checks the three deterministic failure counts above, and requires zero failures from the submitted-code controls. It prints `ATTACK sign-17-2 ... CONFIRMED`.

## sign-17-3: A failed message digest leaves the previous digest in the verifier

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: OPSsig-128, -256 and -512; reference and AVX2 implementations
Discovery: Moderate
Exploitation: If the digest helper fails after an earlier verification in the same process, a signature on the earlier message verifies for a new message; the trigger is an allocation failure inside the contest's hash helper
Credit: Hao Yan, Yuhang Cao, Yao Tong and Qiaosheng Zhang, Shanghai AI Laboratory, with GLM 5.3, Kimi 3.1 Pro and in-house model assistance
Date: 2026-11-16
Original source: [Cao et al.'s PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/EEK7CDO5YWQBFH3HF3WV3QUSKH4YNXVY/)
Follow-up source: [OPS-SIG team's 2026-11-19 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/L2GLZ7TNWU3236VSEA6FI2DWM4PPCXSE/)

The verifier computes the message representative `µ` with `crh(mu, CRHBYTES, tmp, inlen)` into a stack buffer and later hashes `µ` with the reconstructed commitment to recompute the challenge (`sign.c:188,215,239–246` in OPSsig-256). `crh` is a `void` wrapper around the contest's `pseudohash` and discards its status (`sign.c:23–26`). `pseudohash` can fail before writing its output: its 1024-bit path allocates a copy of the input and returns `MEMORY_ALLOCATION_FAILED` if that allocation fails, or `HASH_FAILED` if its HMAC step fails (`auxfunc.c:358–370`), and it writes the caller's buffer only at the end (`:436–439`). The verifier then carries on with whatever `mu` held. The AVX2 trees have the same wrapper.

With the archived reference code at all three levels, a signature on message A was accepted for a different message B when the digest's internal allocation failed during the verification of B, immediately after verifying A in the same process. Without the failure, and with the failure after the stack had been overwritten, B was rejected. The reused value is the previous digest left in the same stack slot, so the outcome depends on the call sequence and the compiler.

The allocation that fails holds a copy of the message, so a long attacker-chosen message can cause it under a memory limit; the outer copy of the same length is checked, and both must be live at once. The candidate's defect is discarding the helper's error. The failure point itself is inside the contest's provisional hash helper, which a replacement may not share.

Reclassified from High to Medium on 2026-11-23. A long attacker-chosen message can cause the failure and the result is an accepted forgery, but the failing allocation is the message copy inside the contest's provisional helper, which a replacement need not make.

In a [2026-11-19 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/L2GLZ7TNWU3236VSEA6FI2DWM4PPCXSE/), the OPS-SIG team agrees that the `crh` wrapper discarded the status of `pseudohash` and that verification could then accept a modified message under the earlier signature. It says all three parameter sets in the reference and AVX2 implementations now check the status of the public-key, message and challenge digest computations and reject verification on failure, with matching checks in key generation and signing, and that an updated package will follow. This records the response; the revised code was not evaluated.

### Reproducing

```sh
sh sign-17/reproduce_stale_digest.sh
```

The witness checks the `void` wrapper in all six trees, then builds each reference level with `malloc` wrapped so that one allocation of the size the digest helper requests can be made to fail. It requires the signature on A to verify for B in that case only, and to be rejected for B without the failure and after the stack is scrubbed.

## sign-17-4: A failed transcript allocation makes reference signing return success with an empty signature

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: OPSsig-128, -256 and -512 reference implementations; the AVX2 implementations return an error
Discovery: Trivial
Exploitation: If the signer's message-sized allocation fails, `sig_sign` returns 0 with signature length 0 and writes no signature; nobody can use the result, and no forgery follows
Credit: Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, with MechCrypto assistance
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/digital-signature/sign-17_OPS-Digital-Signature-Algorithm)

The reference signer copies `tr`, the context prefix and the whole message into a heap buffer before hashing them: `tmp = malloc(CRHBYTES + prelen + mlen)`, followed by `if(tmp == NULL) return -1` (`sign.c:104–106` in OPSsig-128, `:92–94` in OPSsig-256, `:94–96` in OPSsig-512). Its caller `crypto_sign_signature` discards that status and returns 0 (`sign.c:189–190`; `:173–174`; `:171–172`). The contest wrapper `sig_sign` initialises `outlen` to 0, treats the zero return as success, stores `outlen` in `*sn_len_bytes` and returns 0 (`SIG_AlgorithmInstance.c:55,62–66`).

When that allocation fails, the caller therefore gets a success status, a signature length of 0 and a signature buffer that was never written. The internal signer sets the length only at its normal exit (`sign.c:166`), and the allocation check is its only early return, so no secret-dependent value is released.

The failing allocation is in the candidate's own code, and its size is the message length plus a small constant. A party that chooses the message can make it fail under a memory limit. The result matches nothing honestly computed: `sig_verify` rejects a zero-length signature (`sign.c:213–214`), and no other party can use it. The harm is to a caller that trusts the status and stores or sends an empty or stale buffer as a signature.

The AVX2 trees return the internal status (`sign.c:219` in OPSsig-128-avx2, `:224` in the other two), so `sig_sign` there returns −4. The reference and AVX2 implementations disagree on this failure.

### Reproducing

```sh
sh sign-17/reproduce_sign_alloc_false_success.sh
```

The script checks the discarded status in the three reference trees, then builds each reference set and OPSsig-128-avx2 from the unmodified sources with `sign-17/reproduce_sign_alloc_false_success.c`. It signs a 64 MiB message normally, and again with the address space capped 32 MiB above its current size, so that the message copy cannot be allocated; there is no allocator interposition. The reference sets return 0 with length 0 and leave the signature buffer unwritten, and the AVX2 build returns −4. It runs in about 25 seconds on Linux.
