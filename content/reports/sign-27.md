<!-- synchronized report: sign-27/report.md -->
Candidate: SQIsignTriangle
Family: Isogeny/quaternion signature
Archive: [SQIsignTriangle.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SQIsignTriangle.zip) (SHA-256: `f4afa484e450e2adf4b5f9c867fb199d0d0e22d66a3eafbc8c4738744fb62c58`)

## sign-27-1: An all-zero signature aborts the verifier process

Severity: Medium
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

Severity: Medium
Status: Lead
Layer: Design
Affected: All four SQIsignTriangle parameter sets' prime-sizing rationale
Discovery: Moderate
Exploitation: Asymptotic result; concrete key-recovery cost unresolved
Credit: Yintong Luo (GitHub @yintong16); underlying algorithm by Benjamin Wesolowski
Date: 2026-09-23
Original source: [GitHub issue #10 and its attached cost model](https://github.com/ngcc-dev/ngcc-harness/issues/10)

Section 5.3 selects `p` by requiring `p^1/2 > 2^λ` and states that the One Endomorphism Problem is equivalent to the underlying isogeny problem. [Wesolowski, ePrint 2026/1486](https://eprint.iacr.org/2026/1486) gives a heuristic `p^(1/3+o(1))` time-and-memory algorithm for that problem. The square-root sizing premise is therefore superseded at all four levels, including the 128- and 160-bit sets. For the 160-bit set, `p=9·2^309−1` gives a bare `p^1/3` exponent of about 104.1; this is **not** the paper's concrete attack cost. The issue's attached model lists the Triangle primes, but uncertain superpolynomial overhead and high memory could close smaller margins. No concrete full-size key recovery or forgery is claimed.

[Mamah's later time–space analysis](https://eprint.iacr.org/2026/1821), revised 2026-09-23, expects Wesolowski's method to improve on the state of the art at NIST Level I within the practical memory ranges studied. At higher levels, memory offsets that advantage in those ranges, although highly parallelized vOW can recover it. The paper does not cost these archived NGCC primes, so this remains a lead rather than a concrete break.

### Reproducing

Compare §5.3 and Table 6 of `sign-27-spec.pdf` with the cited paper and [issue model](https://github.com/user-attachments/files/32554686/w26_estimate.py).

## sign-27-3: A known signature transfers to a new message in about 2^(lambda/2) work

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All four SQIsignTriangle parameter sets
Discovery: Moderate
Exploitation: About 2^64, 2^80, 2^128, or 2^256 hash trials at the 128-, 160-, 256-, or 512-bit levels
Credit: Tako Boris Fouotsa
Date: 2026-09-26
Original source: [Fouotsa's PKC Forum post and attached analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/F3RT6SYIAB7MLENH3OUBX6OSWQQTJ2LE/)

A signature exposes its response degree `q`; its auxiliary curve and torsion data recover the same commitment independently of the message. Verification binds a message only by hashing `(j(E_pk), j(E_com), message)` to `(c1,c2)` and checking `q mod c1 = c2`. A forger therefore keeps any valid signature and searches for a different message whose challenge satisfies that single congruence.

Each challenge component is only `lambda/2` bits: the implementation sets `byte_len = SECURITY_BITS / 16` and imports that many bytes into each integer, agreeing with the specification's challenge interval of size `2^(lambda/2)`. For fixed `q` and `c1`, exactly one `lambda/2`-bit value of `c2` succeeds, so the expected search is about `2^(lambda/2)` rather than the claimed `2^lambda`. A chosen-message signing query supplies the starting signature, making this a direct EUF-CMA attack. It violates every claimed security level and is therefore Critical, even though the larger instances remain computationally infeasible.

### Reproducing

```sh
python3 sign-27/reproduce_modular_challenge.py
```

The witness checks the archived verifier and challenge-width expressions, prints the four full-size costs, constructs two distinct accepting challenge pairs for one response degree, and runs the exact hash-to-prime/congruence search at a scaled 16-bit security parameter.

## sign-27-4: Distinct challenges can share the identical response, invalidating special soundness

Severity: High
Status: Confirmed
Layer: Design
Affected: The SQIsignTriangle special-soundness argument for all four parameter sets
Discovery: Moderate
Exploitation: Proof failure; no attack beyond sign-27-3 is claimed
Credit: Tako Boris Fouotsa
Date: 2026-09-26
Original source: [Fouotsa's PKC Forum post and attached analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/F3RT6SYIAB7MLENH3OUBX6OSWQQTJ2LE/)

The proof claims that two accepting transcripts with the same commitment and distinct challenges yield two different response isogenies, except with negligible probability. That implication is false. In the submitted hash-to-challenge implementation, given one response of degree `q`, choose any different accepted prime `c1'` and set `c2' = q mod c1'`; the unchanged response is valid for the distinct challenge `(c1',c2')`. In the proof's shifted interval description, one instead samples `c1'` until this remainder lies in the stated interval. Composing the two identical responses in the extractor produces a scalar endomorphism, not the required non-scalar witness.

This is a deterministic counterexample to the stated two-special-soundness claim, not merely a loose probability bound. It is closely related to sign-27-3 and does not establish an additional faster forgery, so it is tracked separately as a proof failure rather than a second Critical break.

### Reproducing

```sh
python3 sign-27/reproduce_modular_challenge.py
```

The script exhibits two distinct prime challenges that accept the same fixed degree and verifies the exact congruences used by Algorithm 4.3 and `verify.c`.
