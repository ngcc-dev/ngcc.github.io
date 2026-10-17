<!-- synchronized report: sign-13/report.md -->
Candidate: GreatWall Signature Algorithm
Family: Symmetric-key (VOLE-in-the-head) signature
Archive: [GreatWall.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/GreatWall.zip) (SHA-256: `814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d`)

## sign-13-1: SHAKE256 capacity reduces GreatWall-512 forgery cost to about 2^256

Severity: Critical
Status: Confirmed
Layer: Design
Affected: GreatWall-512s and GreatWall-512f
Discovery: Moderate
Exploitation: Approximately 2^256 classical Keccak evaluations and one signing query
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-30
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UCS5CCGZNZYKBBJZAE6PKT275GPRPGGP/)
Follow-up source: [GreatWall team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GRYYNLVAGU7VH5LLUWN7XY4EE4SSOQTL/)

GreatWall specifies `H1 : {0,1}* -> {0,1}^{2λ}` as collision resistant and instantiates every hash with SHAKE256 when `λ>128` (§2.3.4). For the 512-bit sets, signing and verification compute `mu=SHAKE256(pk || m || 0x01,1024)` (Algorithms 2 and 13; `faest.c:351–355,542–546`). The 1024-bit output does not raise SHAKE256's 512-bit sponge capacity.

For the fixed public-key prefix, a birthday search over one controlled rate block finds two post-permutation states with equal capacity in about `2^256` work. A second block cancels their public rate difference, making the complete states equal before common padding. The resulting distinct messages have the same `mu`; a signature requested on one therefore verifies unchanged on the other. This is a one-query EUF-CMA forgery at about `2^256` classical work (about `2^170.7` generic quantum queries), below GreatWall's 512-bit classical claim and therefore Critical.

### Proposed fixes

The team acknowledges the SHAKE256 strength limit in its submitted, provisional hash instantiation and says it will clarify the hash requirements for each parameter set and instantiation. This proposed clarification is recorded without evaluating a revised candidate.

### Reproducing

```sh
python3 sign-13/reproduce_shake_capacity.py
```

The witness checks the archived SHAKE256 selection and message-hash path, then executes the exact two-block construction in a scaled permutation model. It certifies the structural attack and full-size generic bound; it does not perform the infeasible `2^256` search.

## sign-13-2: Malformed public-key padding aborts verification

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All eight profiles in both reference and optimized GreatWall source trees under the submitted build flags
Discovery: Trivial
Exploitation: Unauthenticated process termination; no forgery or memory corruption
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-05
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UQJ3OVIKPMTVMMWCZ2NDHRUH2HYSHVS7/)
Follow-up source: [GreatWall team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GRYYNLVAGU7VH5LLUWN7XY4EE4SSOQTL/)

`sig_verify` unpacks attacker-supplied public-key field elements through `faest_unpack_public_key` (`faest.c:117–130,609`). The `block*_load_to_block` routines use live `assert` statements to validate their high padding bits; the submitted Makefiles do not define `NDEBUG`. A noncanonical public key therefore terminates the verifier with `SIGABRT` instead of returning invalid.

The local witness generates an honest GreatWall128f signature, checks the valid-key control, and forks a fresh verifier for each of the two field-padding bytes. Both mutations reach the assertion and abort. The forum post additionally reproduced reference 128s/128f/192f/256f and optimized 128f; the remaining source trees contain the analogous assertion.

### Proposed fixes

The team reports fixing the implementation-level issue in its [updated source](https://github.com/GreatWall-Crypto/NGCC-GreatWall). This change is recorded without evaluating the revised code.

### Reproducing

```sh
make -C sign-13
python3 sign-13/reproduce_malformed_pk_abort.py
```

## sign-13-3: Unindexed internal GGM nodes enable multi-target seed recovery below the claimed levels

Severity: Critical
Status: Probable
Layer: Design
Affected: All eight profiles (GreatWall-128s/f, -192s/f, -256s/f and -512s/f), reference and optimized trees
Discovery: Moderate
Exploitation: Opened-target counts from real signatures and a reduced-width (2^20) parent-seed recovery with the submitted code; no full-width search or end-to-end forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

GreatWall commits to all VOLE seeds with one batched GGM tree. Algorithm 4 (physical p. 17) expands every internal node with the same map `(K_{2a+1}, K_{2a+2}) := PRG(K_a || iv_vole; 2λ)`, and Algorithm 14 (p. 26) reconstructs the tree with that map. Neither the node position nor the level enters the PRG, and `iv_vole` is the same for every node of a signature. The implementation matches: `expand_chunk` takes only a seed and the IV (`vector_com.c:60`), gives every node the signature IV (`vector_com.c:80`), and serves both the signer's expansion and the verifier's (`vector_com.c:579,822`). The file is byte-identical across all eight profiles in both source trees. BAVC.Open (Algorithm 12) publishes the sibling seed of every hidden node that has exactly one hidden child, so a signature contains `T <= T_open` PRG outputs whose parents are secret.

A recovered parent is therefore valid for whichever opened seed it hits. The attacker guesses a λ-bit `K`, computes `PRG(K || iv_vole)` once, and looks up the left half among all opened left children and the right half among all opened right children of the signature. A hit yields a hidden parent and hence its hidden child. Expanding that child reaches at least one hidden leaf, which the attacker confirms against the published leaf commitment. The hidden leaf seed completes that vector's VOLE secret `u_i`. The public correction `c_i = u_0 xor u_i` gives `u_0`, and `d xor u_0[0..l)` is the witness `w = (pt, x1)`, which contains the signing key `pt`. The expected cost against one signature is `2^λ/(T+1)` PRG evaluations. Signatures cannot be pooled, because each has its own `iv_vole`.

The median opened-target counts of the submitted KAT signatures are 98/107 (128s/128f), 173/163 (192s/192f), 233.5/221 (256s/256f) and 474/459 (512s/512f). These give `2^121.37`/`2^121.25`, `2^184.56`/`2^184.64`, `2^248.13`/`2^248.21` and `2^503.11`/`2^503.16`, below the classical levels of 128, 192, 256 and 512 bits that Table 3 (p. 31) claims for each variant. GreatWall-192 stays above the 128-bit NGCC floor but falls below its own 192-bit claim. The 128-, 256- and 512-bit sets fall below their required levels outright.

The status is Probable. The reduced-width experiment runs the submitted commitment, opening and expansion code, but no full-width search or scaled end-to-end forgery was run. The multi-target cost is the expected position of the first hit among the `T` genuine targets (an order statistic); it is not a generic proof-tightness term. The general need for per-node separation in multi-instance GGM PPRFs is discussed by Bui et al. ([ePrint 2024/252](https://eprint.iacr.org/2024/252)). This submission exposes the unseparated targets in every signature, and the resulting costs fall below its concrete claims.

### Reproducing

```sh
python3 sign-13/reproduce_ggm_multitarget.py tree
```

The script checks the unindexed expansion in all 16 `vector_com.c` files and in the text of Algorithms 4 and 14. It then signs with all eight `lib/*.so` libraries, counts the opened seeds (cross-checked against a recomputation from `chall3`, with honest-verify and bit-flip-reject controls) and requires the resulting exponents to agree with the KAT values to within 0.25 bits. Next, it builds a temporary GreatWall128s copy whose PRG keys are truncated to 20 bits, and recovers a hidden parent, confirmed by a published leaf commitment, in 32/32 genuine openings by searching all opened seeds at once. A single-target control runs about `(T+1)/2` times slower, a wrong-IV control recovers nothing, and every result is checked against ground truth. The default run takes about 1 minute. `NGCC_LONG=1` signs 100 times per profile (20 at 512) and repeats the recovery at 128s, 128f, 192f and 256f.

## sign-13-4: Unindexed leaf commitments enable multi-target seed recovery below the claimed levels

Severity: Critical
Status: Probable
Layer: Design
Affected: All eight profiles (GreatWall-128s/f, -192s/f, -256s/f and -512s/f), reference and optimized trees
Discovery: Moderate
Exploitation: Leaf-target counts from real signatures and a reduced-width (2^20) hidden-leaf seed recovery with the submitted code; no full-width search or end-to-end forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

GreatWall derives each committed seed and its leaf commitment as `(sd_{i,j}, leafcom_{i,j}) := H0(K_{L-1+t} || iv_vole)` (Algorithm 4 line 20, physical p. 17; Algorithm 14 line 36, p. 26). Section 2.3.4 (p. 27) defines `H0 : {0,1}^{λ+128} -> {0,1}^λ x {0,1}^{2λ}`, so the input has no room for the leaf position `t` or the VOLE-vector number `i`. The implementation matches. `write_leaf` calls `expand_chunk(1, 1, 3, iv, ...)` (`vector_com.c:362`). The leaf PRG absorbs only `K || iv || 0x00` (`hash.h:125–127`). The signer and the verifier commit every leaf position with this one function (`vector_com.c:594,832`), and the file is byte-identical across all eight profiles in both source trees. Every signature publishes the commitments `hleaf_0, ..., hleaf_{τ-1}` of the τ hidden leaves (Algorithm 14 line 11), and the iv is the same for all of them.

The attacker guesses a λ-bit `K`, computes `H0(K || iv_vole)` once, and compares its 2λ-bit commitment half with all τ published hidden-leaf commitments of the signature. Because the commitment is 2λ bits wide, a match identifies the hidden seed `sd_{i,I_i}` of vector `i`. That seed completes the vector's VOLE secret `u_i`. The public correction `c_i = u_0 xor u_i` gives `u_0`, and `d xor u_0[0..l)` is the witness `w = (pt, x1)`, which contains the signing key `pt`. The expected cost against one signature is about `2^λ/τ` H0 evaluations. Signatures cannot be pooled, because each has its own `iv_vole`.

This gives `2^124.54`/`2^124.00` for 128s/128f (τ = 11/16), `2^188.00`/`2^187.42` for 192s/192f (τ = 16/24), `2^251.54`/`2^251.00` for 256s/256f (τ = 22/32) and `2^506.54`/`2^506.00` for 512s/512f (τ = 44/64). All are below the classical levels that Table 3 (p. 31) claims for each variant. GreatWall-192 stays above the 128-bit NGCC floor but falls below its own 192-bit claim. The 128-, 256- and 512-bit sets fall below their required levels outright.

The status is Probable. The reduced-width experiment runs the submitted commitment, opening and H0 code, but no full-width search or scaled end-to-end forgery was run. The cost is the expected position of the first hit among τ genuine targets; it is not a generic proof-tightness term.

### Reproducing

```sh
python3 sign-13/reproduce_ggm_multitarget.py leaf
```

The script checks the unindexed H0 call in all 16 `vector_com.c` files, the leaf PRG input in `hash.h`, and the text of Algorithms 4 and 14 and Section 2.3.4. It signs once with each of the eight `lib/*.so` libraries, confirms τ distinct published leaf commitments (with honest-verify and bit-flip-reject controls) and prints the costs. It then builds a temporary GreatWall128s copy whose PRG keys are truncated to 20 bits, and recovers a hidden leaf seed in 32/32 genuine openings by searching all τ commitments at once. A single-target control runs about `(τ+1)/2` times slower, a wrong-IV control recovers nothing, and every result is checked against ground truth. The default run takes about 1 minute, and `NGCC_LONG=1` extends the recovery to 128f, 192f and 256f.
