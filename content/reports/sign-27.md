<!-- synchronized report: sign-27/report.md -->
Candidate: SQIsignTriangle
Family: Isogeny/quaternion signature
Archive: [SQIsignTriangle.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SQIsignTriangle.zip) (SHA-256: `f4afa484e450e2adf4b5f9c867fb199d0d0e22d66a3eafbc8c4738744fb62c58`)

## sign-27-1: An all-zero signature aborts the verifier process

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All four submitted reference levels; independently rerun on SQIsignTriangle_lvl1
Discovery: Trivial
Exploitation: Remote denial of service where untrusted signatures reach an unisolated verifier; no forgery or key recovery shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The submitted verifier passes attacker-controlled encoded signature data to `compressed_aux_basis_from_bytes`, which asserts that the decoded exponent `e_rsp` is in range. An all-zero signature fails that assertion and calls `abort()` instead of returning invalid-signature status. The existing bounded security sweep recorded the same assertion in all four levels. Rebuilding level 1 from source reproduced exit code 134; its honest KAT passes. This is a process-availability flaw only, and the result with assertions disabled has not been established.

### Reproducing

```sh
make -C sign-27 lib/libSQIsignTriangle_lvl1.so
make -C security ngcc_security
security/ngcc_security sign-27/lib/libSQIsignTriangle_lvl1.so sig-zero
```

The last command intentionally aborts with `encode_verification.c:216` and exit status 134. `make -C sign-27 test-SQIsignTriangle_lvl1` is the passing honest-signature control.

## sign-27-2: Triangle prime sizing relies on the former square-root attack cost

Severity: Critical
Status: Lead
Layer: Design
Affected: Level-1 has a published concrete below-target lead; all four parameter sets use the superseded prime-sizing rationale
Discovery: Moderate
Exploitation: The published fixed-memory estimate for the exact Level-1 prime straddles the consistently counted AES-128 gate target; no full-size key recovery has been run
Credit: Yintong Luo (GitHub @yintong16); concrete reassessment by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; underlying algorithm by Benjamin Wesolowski
Date: 2026-09-23
Original source: [GitHub issue #10 and its attached cost model](https://github.com/ngcc-dev/ngcc-harness/issues/10)

Section 5.3 selects `p` by requiring `p^1/2 > 2^λ` and states that the One Endomorphism Problem is equivalent to the underlying isogeny problem. The submitted Level-1 prime already fails that stated rule: for `p = 5·2^248-1`, `p^1/2 ≈ 2^125.2 < 2^128`. The following concrete-security paragraph lists only `λ ∈ {160,256,512}`, omitting the 128-bit set. [Wesolowski, ePrint 2026/1486](https://eprint.iacr.org/2026/1486) improves the underlying problem to `p^(1/3+o(1))` time and memory. [Ouyang, Wei and Xu](https://arxiv.org/abs/2610.21488) subsequently proved the smoothness property used by the algorithm, making that asymptotic result unconditional.

[Mamah's concrete analysis](https://eprint.iacr.org/2026/1821) evaluates the **exact** submitted Level-1 prime `p = 5·2^248-1`. With at most `2^80` stored entries it estimates `2^[138.78,143.51]` gates for the full attack. The same table estimates the old square-root HyperSolver attack at `2^143` gates on that prime, equal to the usual AES-128 key-search reference when both sides are counted in elementary gates. Thus the submitted prime already had essentially no margin under the old estimate, while the new estimate gains between zero and about 4.2 bits. Its interval straddles the target, but its midpoint, about `2^141.1`, is below it. This supplies a quantified candidate-specific route and therefore a **Critical Lead**, but not a confirmed break.

[SQIsign v3](https://sqisign.org/spec/sqisign-20260901.pdf) now uses approximately 326-, 505- and 669-bit primes for 128-, 192- and 256-bit targets. This is independent parameter-selection evidence, not an attack threshold for SQIsignTriangle. The 160-, 256- and 512-bit profiles use the same superseded sizing rule, but Mamah's practical-memory study does not give candidate-specific below-target costs for them. No full-size key recovery or forgery was run.

Reclassified from Medium to Critical on 2026-10-16. The status remains Lead because the estimate is model-dependent and straddles the target.

### Reproducing

Compare §5.3 and Table 6 of `sign-27-spec.pdf` with the cited papers and [issue model](https://github.com/user-attachments/files/32554686/w26_estimate.py). The submitted Level-1 prime is exactly the Level-I prime used in Table 4 of the concrete analysis.

## sign-27-3: A known signature transfers to a new message in about 2^(lambda/2) work

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All four SQIsignTriangle parameter sets
Discovery: Moderate
Exploitation: About 2^64, 2^80, 2^128, or 2^256 classical hash trials; about 2^(lambda/4) generic quantum queries
Credit: Tako Boris Fouotsa
Date: 2026-09-26
Original source: [Fouotsa's PKC Forum post and attached analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/F3RT6SYIAB7MLENH3OUBX6OSWQQTJ2LE/)
Follow-up source: [SQIsignTriangle team's confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AD6OWNGXIO365OS2TU27TNSBKKCJZV4T/)

A signature exposes its response degree `q`; its auxiliary curve and torsion data recover the same commitment independently of the message. Verification hashes the public-key curve, commitment curve and message to `(c1,c2)`, then checks `q mod c1 = c2`. A forger therefore keeps any valid signature and searches for a different message whose challenge satisfies that single congruence.

Each challenge component is only `lambda/2` bits: the implementation sets `byte_len = SECURITY_BITS / 16` and imports that many bytes into each integer, agreeing with the specification's challenge interval of size `2^(lambda/2)`. The verifier checks `(q - c2) mod c1 = 0` without requiring `c2 < c1`, so several `c2` values can succeed for one `c1`; either codomain component can also supply `c1`. The search still costs on the order of `2^(lambda/2)` classical trials, rather than the claimed `2^lambda`. Grover search uses about `2^(lambda/4)` generic quantum queries or iterations; no end-to-end gate cost is claimed. A chosen-message signing query supplies the starting signature, making this a direct EUF-CMA attack. It violates every claimed classical security level and is therefore Critical, even though the larger instances remain computationally infeasible.

### Reproducing

```sh
python3 sign-27/reproduce_modular_challenge.py
```

The witness checks relevant expressions in the archived source, prints the four full-size costs, constructs two distinct accepting challenge pairs for one response degree, and models the hash-to-prime/congruence search in Python at a scaled 16-bit security parameter. It does not call the submitted verifier.

## sign-27-4: Distinct challenges can share the identical response, invalidating special soundness

Severity: Medium
Status: Proof gap
Layer: Design
Affected: The SQIsignTriangle special-soundness argument for all four parameter sets
Discovery: Moderate
Exploitation: Deterministic counterexample to the stated soundness lemma; no additional forgery demonstrated
Credit: Tako Boris Fouotsa
Date: 2026-09-26
Original source: [Fouotsa's PKC Forum post and attached analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/F3RT6SYIAB7MLENH3OUBX6OSWQQTJ2LE/)
Follow-up source: [SQIsignTriangle team's confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AD6OWNGXIO365OS2TU27TNSBKKCJZV4T/)

The proof claims that two accepting transcripts with the same commitment and distinct challenges yield two different response isogenies, except with negligible probability. That implication is false. In the submitted hash-to-challenge implementation, given one response of degree `q`, choose any different accepted prime `c1'` and set `c2' = q mod c1'`; the unchanged response is valid for the distinct challenge `(c1',c2')`. In the proof's shifted interval description, one instead samples `c1'` until this remainder lies in the stated interval. Composing the two identical responses in the extractor produces a scalar endomorphism, not the required non-scalar witness.

This is a deterministic counterexample to the stated two-special-soundness claim, not merely a loose probability bound. It does not establish an additional forgery, so it is tracked as a proof failure rather than a Critical break.

### Reproducing

```sh
python3 sign-27/reproduce_modular_challenge.py
```

The script models two distinct prime challenges that accept the same fixed degree and checks the corresponding congruences. It checks the submitted source expressions statically but does not execute `verify.c`.

## sign-27-5: Response rescaling gives a practical fresh-message forgery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All four submitted SQIsignTriangle parameter sets
Discovery: Non-trivial
Exploitation: One signing query for an eligible response, followed by public verifier-scale work; all 12 full-size trials forged within one second on this host
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-27
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DYDMQ7SEI5DPVVP6IL27J63YODLVUPE3/) and [pinned public analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/66c991978995c17d1514825a9e9d2ff6810bb22a/SQIsignTriangle)

The specified response has a scaling symmetry. Verification constructs its kernel from `([q]P_pk,P_aux)` and `([q]Q_pk,Q_aux)`. Given an odd replacement `q'` with the same bit length, set `u = q' q^-1 mod 2^e` and multiply all four serialized auxiliary-basis coefficients by `u mod 2^e`. Both reconstructed kernel generators are then multiplied by the same unit, so the subgroup, quotient, and unordered codomain `j`-invariants are unchanged.

SQIsignTriangle claims EUF-CMA security (§6.4, Theorem 4), which one signing query suffices to violate. For a fresh target message, the attacker publicly recovers the two codomain factors and their challenges `(c1,c2)`, then chooses an odd `e`-bit `q'` satisfying `q' = c2 mod c1`. The public condition `2^(e-1) > 2c1` is sufficient to ensure such a representative. The verifier reconstructs the original kernel but accepts the replacement response against the target challenge. No message search is needed; this is a direct EUF-CMA forgery rather than signature malleability.

We reran three deterministic fresh-key trials at each of the 128-, 160-, 256-, and 512-bit sets. Every first response met the sufficient condition; every transformed signature was accepted on its unqueried target and rejected on its source, while the genuine signature showed the opposite behavior. The observed response exponents were 219–895 and all 12 public transformations completed in under one second on this host. The submission gives no lower-tail bound for honest response sizes, so this establishes practical success on the tested executions rather than a proof that every first response is eligible; an attacker can request another signature after an ineligible response.

### Proposed fixes

The [SQIsignTriangle team's 2026-09-29 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LPKVMFEKL6SOLLJBMLYNMXCNQNL5R4P7/) proposes checking the actual response degree for the challenged codomain factor using Weil pairings and the degree bound, and clarifying a canonical commitment encoding for the hash input. It credits Tako Boris Fouotsa with the earlier missing-check observation and canonical-encoding proposal. This records the submitters' proposal without evaluating it.

### Reproducing

```sh
make -C sign-27 exploit-response-rescaling
```

The wrapper checks out the pinned public reproducer, which builds the unmodified submitted verifier and runs the four source/target controls for three fresh keys at every level. It requires Git, GNU Make, Python 3, GCC, and GMP development headers.
