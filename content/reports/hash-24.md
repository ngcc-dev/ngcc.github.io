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
