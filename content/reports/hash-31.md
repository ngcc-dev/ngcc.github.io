<!-- synchronized report: hash-31/report.md -->
Candidate: The ZC-DMC Hash Function
Family: Symmetric (feed-forward sponge)
Archive: [ZC-DMC.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/ZC-DMC.zip) (SHA-256: `b6da323d388d3411b882228152f25626999502b8c246cc0c9b64a0a9d72eaaac`)

## hash-31-1: Cross-domain distinguisher between ZC-1536-512 and ZC-1536-768

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified ZC-DMC-1536-512 and ZC-DMC-1536-768 construction
Discovery: Moderate
Exploitation: Moderate
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CVL24T5A4ILSD6V2GACF73MENNFQC3JB/)

The two instances share the same 1536-bit permutation and zero initial state, while moving the rate/capacity feed-forward boundary. Further extension to Tsinghua Hash Lab's analysis: take a common first 704-bit block (zero-extended to 960 bits for the 512 profile), then a zero block. After these two absorptions the states differ only at bits 704–959, by `D = P(B1)[704:960]`. Putting `D` in that region of the 512 profile's third block makes both final permutation inputs equal. Feed-forward leaves their first 704 state bits equal, so the first 64-bit squeeze blocks agree. The first-block counter value 13 gives the four-bit suffix needed to make both final blocks valid under the mandatory `M || 01 || 10*1` padding.

The official 512- and 768-bit `CryptHash` libraries return the same first eight digest bytes, `7a07b396b47dfec4`, for the constructed messages. A one-bit control differs. This is a cross-profile distinguisher (ideal probability `2^-64`), **not** a same-instance or full-digest collision.

Follow-up analysis: the [Iphe Algorithm Group's cross-rate note, posted by 崔灏睿 on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/) gives an independent three-block ZC-DMC witness. The [ZC-DMC team's response on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/R4Y2U6SYSDUPFSVPGYIYSXGWVGQKVIDJ/) acknowledges the relation; this report concerns the archived zero-IV submission.

### Proposed fixes

The [ZC-DMC team's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/R4Y2U6SYSDUPFSVPGYIYSXGWVGQKVIDJ/) proposes distinct three-bit IV tags for the profiles. This section records the proposal without evaluating it.

### Reproducing

From the repository root, run `make -C hash-31 exploit`. The witness uses only the two official archived hash libraries for its verdict and prints `CONFIRMED hash-31-1`.

## hash-31-2: A conditional iterative trail gives a 2^384 full-round collision estimate

Severity: High
Status: Lead
Layer: Design
Affected: Full-round ZC-DMC-1536-1024; reduced-round estimates for the other sets
Discovery: Moderate
Exploitation: Estimated 2^384 work, conditional on multi-round trail assumptions
Credit: Qinghe Crypto Group
Date: 2026-09-29
Original source: [Qinghe Crypto Group's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/UPLLMJ35VZ5K7U2BZ7RHJMVYG2ZSRN2Z/)

For ZC-1536, the input difference `Delta A_0[0] = 0x1111111111111111` survives the linear layer. At each of its 16 active bit positions, the sequential χ mapping preserves the difference exactly when the two other input bits are `0,1`, a probability of `1/4`; the one-round trail therefore has weight 32. Capacity-only feed-forward leaves this rate difference unchanged, after which a message-block difference can cancel it and merge the states.

Under a `2^-32` independent probability per round, the reported 7-, 11-, and 12-round costs are `2^224`, `2^352`, and `2^384`. The full 12-round ZC-DMC-1536-1024 estimate is below its claimed 512-bit collision security. The local transition, linear invariance, feed-forward algebra, and arithmetic check out, but full-round satisfiability, independence, and the valid-message distribution remain unproved. Because the submitted IV is zero, the required first-round bit conditions may not all be directly message-controlled; a prefix block may be needed, and the existence of a suitable prefix is part of the unresolved satisfiability question. This is therefore a High Lead rather than a confirmed full collision.

### Reproducing

```sh
python3 security/zc_iterative_differential.py
```

The certificate exhausts the three-bit χ inputs and checks both reported masks against the linear rotations: the 16-active-position mask used above has weight 32 per round, while the all-ones mask used for the reported ZC-1280 reduced-round trail has 64 active positions and weight 128 per round. It then prints the unresolved multi-round limitation.
