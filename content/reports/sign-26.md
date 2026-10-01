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

[Mamah's later time–space analysis](https://eprint.iacr.org/2026/1821), revised 2026-09-23, expects Wesolowski's method to improve on the state of the art at NIST Level I within the practical memory ranges studied. At higher levels, memory offsets that advantage in those ranges, although highly parallelized vOW can recover it. The paper does not cost these archived NGCC primes, so this remains a lead rather than a concrete break.

### Reproducing

Compare §5.1 and §6.4.1 of `sign-26-spec.pdf`, especially their `p^1/2` premise, with the cited paper and all four prime sizes in the specification.

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
