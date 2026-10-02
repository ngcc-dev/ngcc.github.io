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

This is a structural distinguisher on the independently specified core permutation, not by itself a collision, preimage, or distinguisher through the prescribed QSH hash interface. The fixed IV and compression-function injection do not give an attacker a chosen full-state permutation input. The same structure also yields full-mode free-start and semi-free-start collisions when the initial state can be chosen, but no sub-generic ordinary collision under QSH's prescribed initialization is presently known.

The [QSH submitters' response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/XUAXWJADVANE33OZYPLNT4IEOLJU4IOJ/) makes the same interface distinction and notes that the fixed IV places the first compression input outside this subspace. The core-permutation finding is unchanged; no whole-hash weakness is inferred from it.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/archive/2026/2152/20260928:060753), Section 7 (revised 2026-09-28), proves the invariant and derives the free-start results.

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

Severity: Critical
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

## hash-24-3: QSH admits full-mode free-start and low-cost semi-free-start collisions

Severity: Medium
Status: Confirmed
Layer: Design
Affected: QSH-512, QSH-768, and QSH-1024
Discovery: Non-trivial
Exploitation: Explicit free-start collisions; theoretical semi-free-start bounds of 2^64, 2^128, and 2^128 compression calls under one chosen reset
Credit: Yufei Yuan, Ruichen Wu, Shanpeng Wei, Junxu Shen, Jinpeng Liu, and Yixin Zhang
Date: 2026-09-28
Reference: [*Structural Analysis of Seven Hash Functions Submitted to the NGCC*, ePrint 2026/2152, revised 2026-09-28](https://eprint.iacr.org/archive/2026/2152/20260928:060753)

For every message block `M` and flag `f`, QSH compression is invertible in the complete incoming state. Given a chosen output `Z`, subtracting the feed-forwarded `M`, inverting the public core permutation, undoing the flag XOR, and subtracting `M` from the right half recovers the unique input state. Two distinct messages can therefore be inverted from the same final state to give explicit collisions in the complete hash mode when each message may use its own full reset.

The revised paper also propagates a four-step periodic-state invariant through padding and tree processing. With one chosen complete reset shared by both messages and every tree node, its semi-free-start search costs at most `2^64`, `2^128`, and `2^128` compression calls for QSH-512, -768, and -1024, respectively, plus 15 inverse-core evaluations and three final compressions. The proof bounds the success probability above 0.39 without assuming uniform outputs.

These are not ordinary collisions for the submitted API: its reset is fixed, while the free-start construction uses separate resets and the semi-free-start construction chooses one common reset. Under the prescribed reset, the paper obtains reusable four-way multicollisions at the complete-CV birthday cost (`2^256`, `2^512`, and `2^512`), which does not lower the ordinary digest collision exponent. The relaxed initialization keeps this at Medium rather than making it a primary hash-claim break.

### Reproducing

The witness independently implements the inverse of the submitted core and reconstructs the paper's two-message free-start collision for all three variants. It checks the published first reset words, distinct resets, and an identical all-zero final state:

```sh
cc -O2 -std=c99 -Ihash-24 hash-24/reproduce_free_start.c -o /tmp/qsh-free-start
/tmp/qsh-free-start
```

The semi-free-start bounds are proof-level results and are not exhaustively searched by this witness.
