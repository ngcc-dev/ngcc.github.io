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
Follow-up source: [MoFang team's revision notice](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/MKUGDOEMKQFY4M7UWJT5EF5AMOCUKITQ/); [Zhang and Liu's ePrint 2026/2886](https://eprint.iacr.org/2026/2886)

MoFang uses the two 576-bit halves of each message block as cipher keys. Both key schedules move words 5 and 7 identically, never apply the S-box to them, and rotate them only by odd amounts. Applying the same two-periodic XOR difference to the corresponding words in both halves therefore cancels from every combined round key, for every chaining value and all 16 rounds.

As a concrete collision, let `M` be 120 zero bytes and let `M'` set bytes 40--47 and 112--119 to `ff`. MoFang-512 maps both to `ebbc07cddba0f381917c62cf0954fd63eb3e162065f61b14baef1a8d09982e5fbbd9f6ce5aac1e7d36d979126e11358c0635f4a8d2bda29e037ed733e1a9aca4`; the same pair collides in every other submitted instance. Because the cancellation is independent of the base key, it also supplies a same-length second preimage for every message of at least 960 bits. Independent differences in words 5 and 7 give 16 equivalent choices per complete message block and multicollisions across blocks.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/archive/2026/2152/20260923:103749), Section 3 (2026-09-23), proves the cancellation for the fixed-output and XOF variants.

The frozen Round 1 archive above remains the target of this finding.

### Proposed fixes

The [MoFang team's revision notice](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/MKUGDOEMKQFY4M7UWJT5EF5AMOCUKITQ/) proposes making the later block's S-box consume the second row rather than the first, regenerating the implementations and KATs, and correcting an Algorithm 4 assignment typo. This section records the proposal without evaluating it.

Zhang Zhihong and Liu Fengyaxuan's [ePrint 2026/2886](https://eprint.iacr.org/2026/2886) (received 2026-11-13) reports that the revised reference implementation keeps the per-round key cancellation, and gives explicit collisions for all six revised variants. The relocated S-box now receives the second half's word-5 difference, so cancellation depends on that half's values. When its words other than 0, 5 and 7 are zero, the difference passes the S-box unchanged, and every input has 16 round-key-equivalent inputs for any common chaining value; outside that domain, classes have at most four. Its colliding 144-byte message pair and digests were checked against the reference C code at commit `bfdc6a89` of the submitters' GitHub repository. The results concern that code rather than the revised specification, whose Algorithm 3 writes the row-1 S-box output into row 0. This entry records the claim without evaluating it.

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

## hash-19-3: Fixed-output wrappers ignore the requested digest length

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: MoFang-256, -512, -768 and -1024; reference and optimized implementations
Discovery: Trivial
Exploitation: A caller that sizes the output buffer from a shorter requested length receives a write beyond it; no secret disclosure or cryptographic break shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; independently reported by LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-17
Follow-up source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/5TTUBC7JEUGTBRABYD53LMM7SHGF664T/), posted after this entry was published

`hash_MDP` and `hash_MDPH` take the requested output length but never read it (reference signatures at `:201`, `:237` and `:236` for the 256/512, 768 and 1024 sources), so `CryptHash` returns 0 and always writes the full 32-, 64-, 96- or 128-byte digest. All eight fixed-output builds do this for 8- and 256-bit requests. The XOF builds honour the requested length.

Fix: return an error unless `digest_len_bits` equals the instance's digest length.

### Reproducing

```sh
sh hash-19/reproduce_digest_length.sh
```

The driver never writes out of bounds itself; it measures the write extent inside a larger buffer.

## hash-19-4: The key expansion applies the specified block transpositions in exchanged positions

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: MoFang-256, -512, -768 and -1024 and the two XOFs; reference implementation (run on MoFang-256 and -768)
Discovery: Moderate
Exploitation: An implementation that follows the printed key expansion computes a different function and reproduces none of the KATs; no security consequence identified
Credit: Zhiqiang Yang, Lin Ao, Yue Li, Xin Yi, Ling Song and Lei Wang, using the CryptVerify tool (Cryptol and SAW)
Date: 2026-11-19
Original source: [Yang et al.'s formal verification report, finding 1](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/7RGEIZ5TI5BTESVHWRVJMTQHX5CMYUB5/attachment/4/FormalVerificationReportonNGCCHashCandidates.pdf)

Figure 5 (§2.4, physical p. 9) numbers each message word (x, y) with x the column and y the row, the convention under which the code's rotation tables equal Tables 3 and 6. In that convention Algorithm 3 (§2.4.4, p. 14) transposes the first block with C[x,y] = B[y, 2x+y] (line 7) and the second with C[x,y] = B[x+2y, x] (line 18). The reference `MessageExpansion1`, which stores word (x, y) as `key[y][x]`, does the opposite: the first block uses `key0[j][(j+2*i)%3]` (`CryptHash_AlgorithmInstance.c:138`, B[x+2y, x]) and the second `key1[(i+2*j)%3][i]` (`:150`, B[y, 2x+y]). Algorithm 4 (p. 15, lines 4, 12 and 23) for MoFang-768 and -1024 is exchanged the same way on all three blocks. The two maps are inverse permutations, and the code's choice fits the printed formulas only if B[x,y] is read as row x, column y, contrary to Figure 5; Table 5 (p. 13) fits either reading.

The shipped MoFang-256 and -768 reproduce all 4,097 KAT_2_12 vectors. With only the transposition expressions changed to the printed formulas in the Figure 5 convention, they reproduce none.

### Reproducing

```sh
sh hash-19/reproduce_spec_mismatch.sh
```

The witness regenerates each KAT_2_12 file with the shipped NGCC generator and uses it only if its canonical SHA-256 equals the official file's entry in `hash-19/kat.sha256`.

## hash-19-5: MoFang-768-XOF output beyond 768 bits does not follow Algorithm 6

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: MoFang-768-XOF for requested lengths above 768 bits; reference and optimized implementations; specification Algorithm 6, lines 17–22
Discovery: Moderate
Exploitation: A request for more than 768 bits returns output that differs from Algorithm 6 from bit 768 onward, and Algorithm 6 itself returns the requested length only for multiples of 768; the 768-bit KATs are unaffected; no security consequence identified
Credit: Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, with MechCrypto assistance; comparison with the code by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/hash-function/hash-19_MoFang-Hash-Function)

Algorithm 6 (physical p. 18) extends MoFang-768-XOF beyond 768 bits by repeating `(L, R) ← CF(L ⊕ 2_n, R, 0)` (line 20) and appending `MSB_t(L) ‖ MSB_t(R)`. Here `t` is 384, except in the last of `λ = ⌊ℓ/768⌋` iterations, where `t = ℓ mod 384` (lines 18–22). Each iteration appends `2t` bits. For `ℓ = 768λ + r` the algorithm returns `768λ + 2(r mod 384)` bits, which equals `ℓ` only when `r = 0`. For `ℓ = 1000` it returns 1,232 bits.

The submitted code returns exactly `⌈ℓ/8⌉` bytes. It emits 96-byte blocks, 48 bytes of L followed by 48 bytes of R, and cuts the last block at the requested length (`MoFang-768-XOF/CryptHash_AlgorithmInstance.c:292–321`). A partial last block therefore comes from L first, not from equal parts of L and R. Before each further compression the code XORs the constant 2 into `in_h`, the R half (`:297`), while line 20 and the code's own absorbing loop (`:267`) apply it to L. The optimized source does the same (`:312`).

With the reference source built unchanged, a 1,000-bit request for "abc" writes 125 bytes, equal to the first 125 bytes of a 1,536-bit request. Moving the constant at line 297 to the L half, as line 20 specifies, changes the 1,536-bit output from byte 96 onward and leaves the first 96 bytes unchanged.

The instance's digest length is 768 bits, so the submitted KATs do not exercise the continuation, and the call does not require an XOF. The reporters identified the output-length error of Algorithm 6.

### Reproducing

```sh
pdftotext -f 18 -l 18 -layout hash-19/hash-19-spec.pdf - | grep -n "mod 384\|CF(L ⊕ 2n , R, 0)"
sed -n '292,321p' "hash-19/MoFang/Implementations/Reference_Implementation/MoFang-768-XOF/CryptHash_AlgorithmInstance.c"
```

This is a source witness.
