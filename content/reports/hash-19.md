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
Follow-up source: [MoFang team's revision notice](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/MKUGDOEMKQFY4M7UWJT5EF5AMOCUKITQ/)

MoFang uses the two 576-bit halves of each message block as cipher keys. Both key schedules move words 5 and 7 identically, never apply the S-box to them, and rotate them only by odd amounts. Applying the same two-periodic XOR difference to the corresponding words in both halves therefore cancels from every combined round key, for every chaining value and all 16 rounds.

As a concrete collision, let `M` be 120 zero bytes and let `M'` set bytes 40--47 and 112--119 to `ff`. MoFang-512 maps both to `ebbc07cddba0f381917c62cf0954fd63eb3e162065f61b14baef1a8d09982e5fbbd9f6ce5aac1e7d36d979126e11358c0635f4a8d2bda29e037ed733e1a9aca4`; the same pair collides in every other submitted instance. Because the cancellation is independent of the base key, it also supplies a same-length second preimage for every message of at least 960 bits. Independent differences in words 5 and 7 give 16 equivalent choices per complete message block and multicollisions across blocks.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/archive/2026/2152/20260923:103749), Section 3 (2026-09-23), proves the cancellation for the fixed-output and XOF variants.

The frozen Round 1 archive above remains the target of this finding.

### Proposed fixes

The [MoFang team's revision notice](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/MKUGDOEMKQFY4M7UWJT5EF5AMOCUKITQ/) proposes making the later block's S-box consume the second row rather than the first, regenerating the implementations and KATs, and correcting an Algorithm 4 assignment typo. This section records the proposal without evaluating it.

### Reproducing

The local witness checks the published pair and a nonzero-base second preimage against all six submitted libraries:

```sh
make -C hash-19 reproduce
```

## hash-19-2: Short-message outputs of MoFang-768 and MoFang-1024 are public byte permutations

Severity: Medium
Status: Confirmed
Layer: Design
Affected: MoFang-768 and MoFang-1024 specification; reference and optimized implementations
Discovery: Moderate
Exploitation: Trivial; for every message of at most 1151 bits, one digest determines 96 bytes of the other; no collision or preimage on a single profile
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

MoFang-768 and MoFang-1024 both use the Hirose double-block-length compression function `CF(L, R, M)`, whose second cipher call encrypts `L ⊕ 1` under the same key `R ∥ M` as the first call on `L` (Algorithm 6, lines 1-5, physical PDF page 18). The instances differ only in their domain values in the last four bits of `L`, `1010` and `1011` (§2.6 and Table 7, page 16; Algorithm 6, lines 7 and 9). Both start with `R = 0`. In the submitted code these are `in_g[2][2] = 10` and `11` (reference `MoFang-768/CryptHash_AlgorithmInstance.c:264` and `MoFang-1024/CryptHash_AlgorithmInstance.c:263`; optimized `:279` and `:278`). The two domain values therefore differ in exactly the bit that the Hirose construction flips between its branches.

A message of at most 1151 bits pads to a single 1152-bit block, so only the final call `CF(L ⊕ 2, R, M_1)` is made (Algorithm 6, line 15). The two instances make the same two cipher calls in the opposite order, so their output halves `L'` and `R'` are swapped. The 768-bit digest keeps the first 48 bytes of each half (line 16). Hence

`MoFang-768(M) = MoFang-1024(M)[64:112] ∥ MoFang-1024(M)[0:48]`.

For longer messages the first block leaves the two chaining states swapped, so the second block uses different keys (`R ∥ M_2`) and the relation stops.

The two named functions are therefore not independent on short inputs, although the specification claims that MDPH achieves optimal indifferentiability from a random oracle (§3, page 20). This is a cross-profile relation of the kind a domain separation is meant to rule out. MoFang-768-XOF uses `1111` and is not related in this way. The relation does not by itself give a collision, preimage or second preimage on one profile.

### Reproducing

```sh
python3 hash-19/reproduce_768_1024_relation.py
```

The script checks the identity through the submitted libraries for every length from 0 to 1151 bits on random and all-zero messages. It requires zero hits from 1152 to 1399 bits and no relation for the MoFang-768-XOF control, and checks the four cited domain constants in the source. It runs in under one second.
