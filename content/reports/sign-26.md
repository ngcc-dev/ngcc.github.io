<!-- synchronized report: sign-26/report.md -->
Candidate: SQIsign2D-push1/2
Family: Isogeny-based signature
Archive: [SQIsign2D-push12.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SQIsign2D-push12.zip) (SHA-256: `98b7e4ffddfe31b5fb0f448345b49228c8d8a7c87078688ba1656b28631448c5`)

## sign-26-1: Prime sizing assumes a superseded square-root isogeny cost

Severity: Medium
Status: Lead
Layer: Design
Affected: All four submitted levels' prime-sizing rationale
Discovery: Moderate
Exploitation: Asymptotic attack applies to the underlying problem; concrete signature/key-recovery cost unresolved
Credit: Yintong Luo (GitHub @yintong16)
Date: 2026-09-23
Original source: [GitHub issue #10](https://github.com/ngcc-dev/ngcc-harness/issues/10)

Section 5.1 chooses the prime size from the then-best classical `p^1/2` endomorphism-ring/isogeny attack; §6.4.1 uses the same estimate for key recovery. [Wesolowski, ePrint 2026/1486](https://eprint.iacr.org/2026/1486) gives a heuristic `p^(1/3+o(1))` time-and-memory algorithm for the underlying supersingular isogeny problem. Thus the submitted `log2 p ≈ 2λ` sizing premise is superseded at **all** four levels, not only Level-3 and Level-4. For example, Level-1 has `log2 p ≈ 254.6`, so the bare `p^1/3` exponent is about 84.9 against its 128-bit claim. This is not a concrete attack cost: the paper warns that superpolynomial overhead and high memory may close smaller margins. The consequence for every actual parameter set remains unresolved; this is a parameter-selection lead, **not** a demonstrated full-size key recovery or forgery.

[Mamah's later concrete time–space analysis](https://eprint.iacr.org/2026/1821), updated 2026-09-23, finds that the optimistic improvement can require prohibitive memory even for generic 256- and 512-bit SQIsign primes. It does not cost these archived NGCC instances, so this remains a lead rather than a concrete break.

### Reproducing

Compare §5.1 and §6.4.1 of `sign-26-spec.pdf`, especially their `p^1/2` premise, with the cited paper and all four prime sizes in the specification.
