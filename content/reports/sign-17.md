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

### Reproducing

```sh
make -C sign-17 reproduce-spec-findings
```

The wrapper transcribes the specified rounding into the otherwise submitted verifier, checks the three deterministic failure counts above, and requires zero failures from the submitted-code controls. It prints `ATTACK sign-17-2 ... CONFIRMED`.
