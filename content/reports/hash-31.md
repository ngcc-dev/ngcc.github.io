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

### Reproducing

From the repository root, run `make -C hash-31 exploit`. The witness uses only the two official archived hash libraries for its verdict and prints `CONFIRMED hash-31-1`.
