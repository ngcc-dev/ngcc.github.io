<!-- synchronized report: hash-24/report.md -->
Candidate: QuantaSylva Hash (QSH)
Family: Symmetric (tree hash, ARX permutation)
Archive: [QSH.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/QSH.zip) (SHA-256: `d2b33441b42825ea10fd374adfdafea64525ad471159b4787c6dc2bd420f05d9`)

## hash-24-1: Full-round core permutation has a one-query invariant-subspace distinguisher

Severity: Low
Status: Confirmed
Layer: Design
Affected: All parameter sets, core permutation only
Discovery: Moderate
Exploitation: One chosen-state permutation evaluation
Credit: ISCAS (archive sender `Cryptanalysts001`)
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BUUGULWWDDQT2XCVX5GICOLHQB5H6CXT/)
Follow-up source: [QSH submitters' 2026-09-24 response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/XUAXWJADVANE33OZYPLNT4IEOLJU4IOJ/)

As [reported on the CryptHash mailing list](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BUUGULWWDDQT2XCVX5GICOLHQB5H6CXT/), the full ChaCha Bahru permutation commutes with translation of the `x2` coordinate. Consequently the subspace in which the four words differing only in `x2` are equal is invariant through every round and the final layer. It has dimension `16w` inside the `64w`-bit state. One evaluation on a chosen member therefore distinguishes the permutation from random with advantage `1 - 2^-1536` for QSH-512 and `1 - 2^-3072` for QSH-768/1024.

This is a structural distinguisher on the independently specified core permutation, not a collision, preimage, or distinguisher through the QSH hash interface. The fixed IV and compression-function injection do not give an attacker a chosen full-state permutation input, and no whole-hash attack is presently known.

The [QSH submitters' response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/XUAXWJADVANE33OZYPLNT4IEOLJU4IOJ/) makes the same interface distinction and notes that the fixed IV places the first compression input outside this subspace. The core-permutation finding is unchanged; no whole-hash weakness is inferred from it.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/2026/2152), Section 7 (2026-09-23), proves the invariant and likewise does not claim a whole-hash attack.

### Reproducing

The witness calls the submitted QSH-512 permutation on the mailing-list input, checks all 48 defining equalities, and also checks the published exact output:

```sh
cc -O2 -std=c99 -Ihash-24/QSH/Implementations/03_Implementations/1_Reference_Implementation/QSH-512 \
  hash-24/reproduce_invariant.c -o /tmp/qsh-invariant
/tmp/qsh-invariant
```

Expected output:

```text
CONFIRMED: full QSH-512 permutation preserves the 512-bit subspace
random-permutation probability: 2^-1536
```

## hash-24-2: Truncated tree chaining values cap QSH second-preimage security

Severity: Medium
Status: Confirmed
Layer: Design
Affected: QSH-512 and QSH-1024 specifications and implementations
Discovery: Moderate
Exploitation: About 2^n / T compression calls for a target with T leaf chunks: approximately 2^462 for QSH-512 and 2^975 for QSH-1024 at the 2^64-bit maximum message length
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-26

QSH-512 and QSH-1024 claim second-preimage security of 512 and 1024 bits (Table 5, physical PDF page 21), which a multi-target attack on the tree's chaining values violates.

Leaf chunks are processed with a wide state, but each chunk passes on only a chaining value truncated to m/2 bits (§5.3, page 15). That value is 512 bits for QSH-512 and 1024 bits for QSH-1024, equal to the digest length (`CryptHash_AlgorithmInstance.c:256,288` in the QSH-512 reference source). The chunk flags mark only chunk start, chunk end and root; the chunk position is not bound (`:282-284`). An attacker hashes candidate full-size replacement chunks and compares each result with all T eligible leaf chaining values of a long target. On a match, the attacker replaces the particular target leaf whose chaining value was hit. Length, padding and tree shape are unchanged, and the remainder of the tree computation is therefore identical. The expected cost is 2^n / T. With the maximum message length of 2^64 bits (page 33), this is about 2^462 and 2^975. The wide-pipe argument on page 30 holds only within a chunk, and the cited tree-hashing results do not bound truncated n-bit node values beyond n bits. QSH-768 is not affected, because its 1024-bit chaining value exceeds its digest length.

### Reproducing

Compare the claim on physical PDF page 21 with the chaining-value truncation on pages 15–16 and at the cited source lines.
