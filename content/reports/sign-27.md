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

[Mamah's later concrete time–space analysis](https://eprint.iacr.org/2026/1821), updated 2026-09-23, finds that the optimistic improvement can require prohibitive memory even for generic 256- and 512-bit SQIsign primes. It does not cost these archived NGCC instances, so this remains a lead rather than a concrete break.

### Reproducing

Compare §5.3 and Table 6 of `sign-27-spec.pdf` with the cited paper and [issue model](https://github.com/user-attachments/files/32554686/w26_estimate.py).
