<!-- synchronized report: hash-19/report.md -->
Candidate: MoFang Hash Function
Family: Symmetric (block-cipher-based)
Archive: [MoFang.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/MoFang.zip) (SHA-256: `dfdd7dd54361fb09e6d0bc47ae6245a9f992f284c56b04ff55d528e2339c9acc`)

## hash-19-1: Round-key cancellation gives deterministic full-round collisions

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All six MoFang hash and XOF instances
Discovery: Moderate
Exploitation: Trivial
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/IK33PEQPGZ4WVC4EZPOPK62ITTYN37ZD/)

MoFang uses the two 576-bit halves of each message block as cipher keys. Both key schedules move words 5 and 7 identically, never apply the S-box to them, and rotate them only by odd amounts. Applying the same two-periodic XOR difference to the corresponding words in both halves therefore cancels from every combined round key, for every chaining value and all 16 rounds.

As a concrete collision, let `M` be 120 zero bytes and let `M'` set bytes 40--47 and 112--119 to `ff`. MoFang-512 maps both to `ebbc07cddba0f381917c62cf0954fd63eb3e162065f61b14baef1a8d09982e5fbbd9f6ce5aac1e7d36d979126e11358c0635f4a8d2bda29e037ed733e1a9aca4`; the same pair collides in every other submitted instance. Because the cancellation is independent of the base key, it also supplies a same-length second preimage for every message of at least 960 bits. Independent differences in words 5 and 7 give 16 equivalent choices per complete message block and multicollisions across blocks.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/2026/2152), Section 3 (2026-09-23), proves the cancellation for the fixed-output and XOF variants.

### Reproducing

The local witness checks the published pair and a nonzero-base second preimage against all six submitted libraries:

```sh
make -C hash-19 reproduce
```
