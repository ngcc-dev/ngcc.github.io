<!-- synchronized report: hash-20/report.md -->
Candidate: MOZI
Family: Symmetric (sponge)
Archive: [Mozi.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Mozi.zip) (SHA-256: `f68c6b73ff4ac064e6bb8a9b74c4bd8a929594c3c48c89e1a65941e03676ea30`)

## hash-20-1: For short messages, the 384-bit digest is a prefix of the 512-bit digest

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified construction and reference implementation, MOZI digest and XOF profiles
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Iphe Algorithm Group's 2026-09-23 forum note](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/)

For the 24-bit message hex `616263` (`abc`), MOZI-384 returns:

`f3aa50e4542947c662f18092b6b4079e489192491a8f13b49ebd108352e49d1da81e938795a675a409083fce63f2eb1f`

MOZI-512 returns that exact 48-byte value followed by:

`69444aab68ec23d14f909ef4ce1b9b63`

For every message shorter than 1024 bits, both variants initialize the same zero state, inject identical padded bytes at the same offset, and apply the same 20-round permutation. The digest length or variant identifier is never absorbed; only the amount returned to the caller differs.

The two functions therefore lack cross-variant domain separation and cannot be treated as independent hashes. No explicit specification claim of cross-profile independence was located, so this is reported as a confirmed composition defect rather than a collision-resistance claim violation.

The same missing domain separation affects the XOF profiles. On the audited short messages, the 384- and 512-profile 256-bit XOF outputs are equal, while shorter outputs are prefixes of the longer XOF streams. This follows from the normative zero initialization, common padding and permutation, and `MSB_l` output rule; it is not only a wrapper artifact.

Follow-up analysis: the [Iphe Algorithm Group's cross-rate note, posted by 崔灏睿 on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/) independently identifies this one-block MOZI-384/MOZI-512 prefix relation.

The archived Round 1 ZIP above remains the subject of this report.

### Proposed fixes

The [Mozi team's 2026-09-28 response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/GLMIC7PHESTDBHE76LMHS47QCAI6I2HT/) proposes a distinct four-bit initialization domain for every variant. This section records the proposal without evaluating it.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C hash-20
tools/ngcc_attack hash-prefix hash-20/lib/libMOZI-384.so hash-20/lib/libMOZI-512.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## hash-20-2: The specified final marker creates cross-rate relations absent from the implementation

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified MOZI-768 and MOZI-1024 constructions; reference implementation is incompatible
Discovery: Moderate
Exploitation: Moderate
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/5657BKOE43VZOJSF47X5KAFZ5E6FA6CI/)
Follow-up source: [Mozi team's correction](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/GLMIC7PHESTDBHE76LMHS47QCAI6I2HT/)

Algorithm 2 places the final marker at the same absolute state bit for every rate. This permits a three-block suffix under one rate to reproduce the same permutation input as a related suffix under another rate. The submitters report 16/16 cross-rate witnesses in an independent model of the specified construction. This is a relation between different MOZI profiles, not a same-profile collision.

The reference code instead places the marker at the first capacity bit, which is bit 1216 for MOZI-768 and bit 960 for MOZI-1024 rather than the specification's common bit 2047. That rate-dependent placement blocks the reported construction, but makes the code deterministically incompatible with Algorithm 2. The public report did not include its 16 witness messages, so the local check confirms the exact marker discrepancy rather than claiming an end-to-end collision reproduction.

The archived submission remains the target of this finding.

### Proposed fixes

The [Mozi team's 2026-09-28 response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/GLMIC7PHESTDBHE76LMHS47QCAI6I2HT/) proposes making the reference code match Algorithm 2, adding per-variant initialization domains, and regenerating the KATs. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C hash-20 reproduce-forum
```

## hash-20-3: Every reference Mozi instance leaks its padded message buffer on every call

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All six Mozi reference instances (384, 512, 768, 1024, 384-XOF and 512-XOF); the optimized implementations stream the message and are not affected
Discovery: Trivial
Exploitation: Unbounded memory growth in a long-running process that hashes repeatedly; no disclosure or corruption
Credit: LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-17
Original source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/LRPFLS5ERJWJALDYWIA4UHE5SDPQEVRU/)

The sponge functions allocate the padded message with `padded_input = malloc(padded_input_len)` (`MOZI-512/CryptHash_AlgorithmInstance.c:161`, returning at `:186`, and the same pattern in the other five) and return 0 without freeing it, so every call leaks a block the size of the padded message. The result of `malloc` is also used without a check, so an allocation failure dereferences a null pointer. With `malloc` and `free` wrapped, 100 calls left 100 live blocks in each of the six reference instances.

Fix: free the buffer before returning.

### Reproducing

```sh
sh hash-20/reproduce_leak.sh
```

## hash-20-4: The α matrix of Section 2.4.2 and the MUL step of Algorithm 4 define different MixColumn maps

Severity: Low
Status: Confirmed
Layer: Design
Affected: Specification §2.4.2, all Mozi instances; the reference and optimized implementations follow Algorithm 4
Discovery: Moderate
Exploitation: An implementation that uses the displayed α matrix computes a MixColumn that differs from the submitted code on 65,280 of 65,536 column inputs; both maps have branch number 5, and no security consequence was identified
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance, in this candidate's specification notes of 2026-09-21; independently reported by Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, using MechCrypto
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/hash-function/hash-20_MOZI)

Section 2.4.2 (physical p. 8) writes MixColumn as a product `M·(a, b, c, d)` whose entries are built from α and α², and defines α by a 4 × 4 binary matrix that maps a nibble `(x0, x1, x2, x3)` to `(x1, x2, x3, x0⊕x1)`. The same section says that the operation "is given formally in Algorithm 4". Algorithm 4 (physical p. 9) and Listing 1 (physical p. 18) use `MUL` instead, which maps `(x0, x1, x2, x3)` to `(x3, x0⊕x3, x1, x2)`. The reference code implements `MUL` (`MOZI-512/CryptHash_AlgorithmInstance.c:34–38`, called from `bitSliceMDS` at `:41–60`), and so does `mul_row` in the optimized code (`Optimized_Implementation/MOZI-384/CryptHash_AlgorithmInstance.c:73–79`).

The displayed product and the twelve steps of Algorithm 4 are the same circuit: with `MUL` in place of α they agree on all 65,536 column inputs. With α as displayed they differ on 65,280 of them. `MUL` is the transpose of the displayed matrix. The two maps are conjugate under a relabelling of the nibble bits, so both give a matrix of branch number 5, but the nibble bits are the state rows that the S-box also uses, so the relabelling is not available to an implementer and the two readings give different round functions.

The conflict is inside the specification. Algorithm 4, Listing 1 and all submitted code agree, and the text names Algorithm 4 as the formal definition; only the α matrix in the prose disagrees. The specification contains no test vectors that would show which is meant.

### Reproducing

```sh
sed -n '34,38p' "hash-20/Mozi/Implementations/Reference_Implementation/MOZI-512/CryptHash_AlgorithmInstance.c"
pdftotext -f 8 -l 9 -layout hash-20/hash-20-spec.pdf - | grep -A8 -e 'where α transforms' -e 'Function MUL'
```

This is a source witness.
