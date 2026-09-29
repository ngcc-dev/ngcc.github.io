<!-- synchronized report: hash-30/report.md -->
Candidate: ZC-DM
Family: Symmetric (feed-forward sponge)
Archive: [ZC-DM.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/ZC-DM.zip) (SHA-256: `47e6297d4d707897c64a75a0b490152b2c67abfb1777d89d225b4bcf58a0063b`)

## hash-30-1: A conditional iterative trail gives a 2^384 full-round collision estimate

Severity: High
Status: Lead
Layer: Design
Affected: Full-round ZC-DM-1536-1024; reduced-round estimates for the other sets
Discovery: Moderate
Exploitation: Estimated 2^384 work, conditional on multi-round trail assumptions
Credit: Qinghe Crypto Group
Date: 2026-09-29
Original source: [Qinghe Crypto Group's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/FCGYUVDJV4QBMGG64KAK6X2QZOZ6W4QX/)

For ZC-1536, the input difference `Delta A_0[0] = 0x1111111111111111` survives the linear layer. At each of its 16 active bit positions, the sequential χ mapping preserves the difference exactly when the two other input bits are `0,1`, a probability of `1/4`; the one-round trail therefore has weight 32. If it persists for `t` rounds, Davies–Meyer feed-forward cancels the identical input/output difference and produces a collision at estimated cost `2^(32t)`.

This gives conditional estimates `2^224`, `2^352`, and `2^384` for 7, 11, and all 12 rounds, respectively. The full-round ZC-DM-1536-1024 estimate is below its claimed 512-bit collision security. The local transition, linear invariance, feed-forward cancellation, weights, and arithmetic check out. The post does not prove that the trail is satisfiable on full valid-message trajectories, that round conditions are independent, or that valid message inputs preserve the assumed distribution. Because the submitted IV is zero, the required first-round bit conditions may not all be directly message-controlled; a prefix block may be needed, and the existence of a suitable prefix is part of the unresolved satisfiability question. The full collision therefore remains a High Lead rather than a confirmed Critical break.

### Reproducing

```sh
python3 security/zc_iterative_differential.py
```

The certificate exhausts the three-bit χ inputs and checks both reported masks against the linear rotations: the 16-active-position mask used above has weight 32 per round, while the all-ones mask used for the reported ZC-1280 reduced-round trail has 64 active positions and weight 128 per round. It then prints the unresolved multi-round limitation.
