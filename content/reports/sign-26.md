<!-- synchronized report: sign-26/report.md -->
Candidate: SQIsign2D-push1/2
Family: Isogeny-based signature
Archive: [SQIsign2D-push12.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SQIsign2D-push12.zip) (SHA-256: `98b7e4ffddfe31b5fb0f448345b49228c8d8a7c87078688ba1656b28631448c5`)

## sign-26-1: Prime sizing assumes a superseded square-root isogeny cost

Severity: High
Status: Lead
Layer: Design
Affected: Level-1 has a well-supported path to a below-target attack; all four levels use the superseded prime-sizing rationale
Discovery: Moderate
Exploitation: Published analysis of a nearby prime and current parameter-selection work indicate a serious Level-1 shortfall, but no candidate-specific below-target cost or full-size key recovery has been established
Credit: Yintong Luo (GitHub @yintong16); concrete reassessment by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; underlying algorithm by Benjamin Wesolowski
Date: 2026-09-23
Original source: [GitHub issue #10](https://github.com/ngcc-dev/ngcc-harness/issues/10)

Section 5.1 chooses the prime size from the then-best classical `p^1/2` endomorphism-ring/isogeny attack; §6.4.1 uses the same estimate for key recovery. [Wesolowski, ePrint 2026/1486](https://eprint.iacr.org/2026/1486) improves the underlying supersingular-isogeny problem to `p^(1/3+o(1))` time and memory. [Ouyang, Wei and Xu](https://arxiv.org/abs/2610.21488) subsequently proved the smoothness property used by the algorithm, making that asymptotic result unconditional.

[Mamah's concrete analysis](https://eprint.iacr.org/2026/1821) estimates `2^[138.78,143.51]` gates for the old 250.3-bit SQIsign Level-I prime with at most `2^80` stored entries. Level-1 uses a nearby 254.6-bit prime. Scaling only the attack's dominant fixed-memory square-root term would add about `(254.6-250.3)/2 = 2.2` bits, suggesting `2^[140.9,145.7]` gates. This is context rather than a candidate-specific attack estimate: it does not recompute the smoothness or root-finding factors, its midpoint is above the roughly `2^143`-gate AES-128 reference, and its interval crosses that reference.

[SQIsign v3](https://sqisign.org/spec/sqisign-20260901.pdf) now uses approximately 326-, 505- and 669-bit primes for 128-, 192- and 256-bit targets. Its deliberately attacker-favourable model supports the seriousness of the parameter concern, but gives a lower bound used for parameter selection rather than an executable attack cost. The higher submitted profiles use the same superseded sizing rule, but no candidate-specific concrete below-target cost is asserted for them here. No full-size key recovery or forgery was run.

Reclassified from Medium to High on 2026-10-16. The status remains Lead because a candidate-specific below-target cost has not been established.

### Reproducing

Compare §5.1 and §6.4.1 of `sign-26-spec.pdf`, especially their `p^1/2` premise, with the cited papers and current parameter analyses. Level-1 has `log2 p = 254.63`; the published concrete row uses `p = 5·2^248-1`, with `log2 p = 250.32`.

## sign-26-2: Missing challenge grinding drops Levels 1 and 3 below their targets

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: SQIsign2D-push1/2 Level-1 and Level-3 reference implementations
Discovery: Moderate
Exploitation: One valid signature, then about 2^123.63 or 2^247.25 hash trials for a fresh-message forgery
Credit: Sun Shuzhou, with GLM-5.3 assistance; Level-1 extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-01
Original source: [Sun Shuzhou's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TUR2W3S22UGBUJXFZYT25VO44PHNFAOJ/)
Follow-up source: [Sun Shuzhou's Level-1 confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/BT6OPELMKDHUTECWKMVPWDI2VCMPAAIG/)

Section 5.1(4) compensates for a challenge space smaller than `2^lambda` by iterating the hash `ceil(2^lambda / 3^e2)` times. This is 21 iterations at Level-1 and 430 at Level-3. The four delivered source trees instead contain the same `hash_to_challenge` function, with one XOF call and no grinding loop (`sign.c:738–769`); signing and verification each call it once (`sign.c:819,1132`).

Given one valid signature, an attacker keeps its public geometric response and searches for a fresh message whose recomputed challenge matches the transmitted challenge. Without the specified compensation, this costs `3^78 = 2^123.63` trials at Level-1 and `3^156 = 2^247.25` at Level-3, below the claimed 128- and 256-bit classical levels. Sun Shuzhou reported the Level-3 shortfall; the same calculation shows that Level-1 is also affected. Levels 2 and 4 have challenge spaces above their respective targets even without grinding. This is a concrete one-query EUF-CMA bound below target, not merely a KAT or encoding mismatch, and therefore is Critical.

Sun Shuzhou subsequently confirmed the Level-1 cost `2^123.63`, which is 4.37
bits below its declared classical target.

The signer and verifier must implement the same `k`-fold hash construction specified in §5.1(4).

### Reproducing

```sh
python3 sign-26/reproduce_grinding_shortfall.py
```

The script reads each submitted exponent and the shared challenge function, checks that exactly one XOF call is made with no grinding loop, and recomputes the four challenge-space bounds and required iteration counts.

## sign-26-3: A failed final split can accept an altered signature in a reused verifier process

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: SQIsign2D-push Level-1 through Level-4 reference verifiers share the byte-identical path; runtime acceptance tested only at Level-3
Discovery: Moderate
Exploitation: An altered signature was accepted for the original message after a valid verification in the same process; changed-message verification failed. No fresh-message forgery is shown.
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/RXZVBGNRTMJFB2AKGZNCVR3Y3ZMTKC5C/)

`splitting_comput` writes `last_step.B.null_point` only when the final split succeeds (`src/hd/ref/hdx/theta_isogenies.c:1375–1376`). The balanced-chain caller ignores its failure result and uses `last_step.B` to compute the codomain (`:1744–1748`). The verifier then hashes that codomain (`src/sqisigndim2/ref/sqisigndim2x/sign.c:1070,1124,1132`). A failed split can therefore consume uninitialized, process-state-dependent data instead of rejecting the signature.

In an NGCC local Level-3 reference run, a valid signature verified, and flipping its first byte then also verified for the *same* message in that process. This runtime acceptance is our observation; the packaged certificate checks only the source path, while the linked forum post is the original report. A changed-message control rejected; an intervening signing call also removed the acceptance. The observed signature alias and process-state dependence merit Medium; they do not establish a fresh-message forgery or a claimed SUF-CMA break. Reject a failed split before using its output.

### Reproducing

```sh
python3 sign-26/reproduce_failed_split.py
```

The certificate checks the unchecked failure path in the submitted source. The process-state-dependent Level-3 acceptance was separately reproduced with a native build; the certificate does not itself replay that run.

## sign-26-4: Noncanonical field, matrix and challenge encodings create aliases

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: SQIsign2D-push Levels 1, 2, 3 and 4 (all four libraries; the decoders are byte-identical across levels)
Discovery: Trivial
Exploitation: Byte-distinct signatures and public keys verify for the same message; no fresh-message forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

SQIsign2D-push claims EUF-CMA (§6.4, p. 39) and states that it cannot provide strong unforgeability (§6.4.3, p. 42). Its decoders nevertheless accept noncanonical encodings that a canonical parser would reject. `fp_decode` reduces an `FP_ENCODED_BYTES` integer modulo `p` without a range check (`gf/ref/gfx/fp.c:195–208`). It decodes the signature's auxiliary-curve coefficient and the public-key curve coefficient (`sqisign.c:307–313,349–378`). `signature_decode` also reduces the four basis-change matrix entries modulo `2^e` and the challenge modulo `3^f` instead of rejecting out-of-range values (`sqisign.c:358–373`). Adding `p` to a curve coordinate, or `3^f` to the challenge field, therefore leaves the decoded signature unchanged. The negated matrix `−M mod 2^e` also verifies.

Native tests at all four levels accepted these aliases for the honest message: signature curve coordinate plus `p`, public-key coordinate plus `p`, challenge plus `3^f`, and `−M`. A changed message, a curve coordinate plus 1 in the signature and in the public key, the challenge plus 1 and a matrix entry plus 1 were all rejected. Appending 16 bytes was also rejected, because `sqisign_verify` checks the signature length (`sqisign.c:666`). Each verification ran as the first library call in its own fresh process, so stale verifier state does not explain the result.

The aliases yield no signature on a new message. They do add byte-level malleability of public keys and of the encoding itself, beyond the response-isogeny malleability that the specification acknowledges. Under the EUF-CMA-only claim this is Medium. A canonical decoder should reject field elements `>= p`, matrix entries `>= 2^e` and challenges `>= 3^f`, and should fix the sign convention of `M`.

### Reproducing

```sh
python3 sign-26/reproduce_encoding_aliases.py
NGCC_LONG=1 python3 sign-26/reproduce_encoding_aliases.py
```

The default run covers Levels 1–3 in about 20 seconds. `NGCC_LONG=1` adds Level 4, whose key generation and signing take about a minute; the full run takes a little over 2 minutes. Every alias and control is verified in a fresh child process.
