<!-- synchronized report: hash-32/report.md -->
Candidate: ZC-EDMC
Family: Symmetric (sponge)
Archive: [ZC-EDMC.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/ZC-EDMC.zip) (SHA-256: `235157f178c0ec885dad4062ee232cdc0d16e95474f05c6f93038fd951ca3712`)

## hash-32-1: The specified and implemented ZC-EDMC mappings differ

Severity: Low
Status: Confirmed
Layer: Design
Affected: All six ZC-EDMC parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Cryptanalysts001, Institute of Software, Chinese Academy of Sciences <yufei2021@iscas.ac.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/6BKFT5FXW3PL3ZXWNQFTLEIQOJSXZTWK/)

The construction prose and Algorithm 3 define the compression mapping with two different six-round halves, `h(g(X) xor (0^r || X_c))`. A displayed equation instead uses `h(h(X) xor ...)`, and the reference implementation invokes the same last-six-round function twice. It therefore implements the displayed equation rather than Algorithm 3.

The submitted permutation constants introduce a second deterministic mismatch: rounds 5--7 and 9--11 of the code's twelve-round schedule are permuted relative to the specification table. The submitters independently modeled the code schedule and reproduced its KATs, and report that changing the inner call from `h` to `g` changes all 22 tested digests for each of the six instances. This is an interoperability and analysis-target defect, not a demonstrated collision or preimage attack.

### Reproducing

The local checker verifies both calls in every reference instance and the exact submitted constant schedule:

```sh
make -C hash-32 reproduce-forum
```

## hash-32-2: A conditional iterative trail gives a 2^384 full-round collision estimate

Severity: High
Status: Lead
Layer: Design
Affected: Full-round ZC-EDMC-1536-1024; reduced-round estimates for the other sets
Discovery: Moderate
Exploitation: Estimated 2^384 work, conditional on multi-round trail assumptions
Credit: Qinghe Crypto Group
Date: 2026-09-29
Original source: [Qinghe Crypto Group's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/4KRD3W3LRMJDQQNL7TYTBCW66P4UUWOY/)

For ZC-1536, the input difference `Delta A_0[0] = 0x1111111111111111` survives the linear layer. At each of its 16 active bit positions, the sequential χ mapping preserves the difference exactly when the two other input bits are `0,1`, a probability of `1/4`; the one-round trail therefore has weight 32. The intermediate capacity feed-forward leaves this rate difference unchanged, and later message-block differences can cancel it and merge the states. The same local trail applies to both mappings present in the archived specification and implementation because it is independent of the round constants and of whether the first six-round half is named `g` or `h`.

Under a `2^-32` independent probability per round, the reported 7-, 11-, and 12-round costs are `2^224`, `2^352`, and `2^384`. The full 12-round ZC-EDMC-1536-1024 estimate is below its claimed 512-bit collision security. The local transition, linear invariance, feed-forward algebra, and arithmetic check out, but full-round satisfiability, independence, and the valid-message distribution remain unproved. Because the submitted IV is zero, the required first-round bit conditions may not all be directly message-controlled; a prefix block may be needed, and the existence of a suitable prefix is part of the unresolved satisfiability question. This is therefore a High Lead rather than a confirmed full collision.

### Reproducing

```sh
python3 security/zc_iterative_differential.py
```

The certificate exhausts the three-bit χ inputs and checks both reported masks against the linear rotations: the 16-active-position mask used above has weight 32 per round, while the all-ones mask used for the reported ZC-1280 reduced-round trail has 64 active positions and weight 128 per round. It then prints the unresolved multi-round limitation.
