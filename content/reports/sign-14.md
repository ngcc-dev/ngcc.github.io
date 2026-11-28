<!-- synchronized report: sign-14/report.md -->
Candidate: Lynxer
Family: VOLE-in-the-head signature
Archive: [Lynxer.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Lynxer.zip) (SHA-256: `34d863f7df8979c4a5e27fcfe657ed54e81905115c0afc8ef749f50af432f928`)

## sign-14-1: A degenerate QuickSilver witness gives universal public-key-only forgeries

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Lynxer-256s/f, -384s/f, and -512s/f; the 160-bit sets use different constraints
Discovery: Non-trivial
Exploitation: Comparable to one honest signature; full-size forgeries reproduced at all six affected parameter sets
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-27
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JMTZL5V7ROPXSFJQWRHIOKLORGI5AJSN/) and [pinned public analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/d03848f40a49a1d1d146e33c88ce251ac092439d/Lynxer)
Follow-up source: [Lynxer team's confirmation and fix](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TJ3HPFROBMZMNMEHDEC3IQRO7R7QHQAQ/)

Additional reference: [Liu et al., ePrint 2026/2235](https://eprint.iacr.org/2026/2235)

The specified QuickSilver relation fails to enforce two nonzero conditions. Set the purported Lynx key to the public constant `c3` and the first S-box output `v1` to zero. Every term in the first constraint then vanishes; the final constraint loses the public target because both its products contain either `v1` or `k+c3`. The attacker publicly evaluates the second S-box to satisfy the sole remaining constraint. This gives a false witness for every public key and message without a signing query or Lynx preimage.

We reran the pinned attack against all six affected full reference parameter sets. Each secret-key buffer was erased before attack construction, direct Lynx evaluation confirmed that the forged key was not a victim preimage, the ordinary submitted verifier accepted the fresh-message signature, and a changed-message control rejected. The 160-bit relations differ and are not claimed to be vulnerable.

The Lynxer team confirms the flaw and reports that the Center for Cryptology Study at Tsinghua University found it independently. The archived Round 1 submission remains the target of this finding.

Liu et al. independently formalize the same null-branch witness mechanism, prove public-key-only forgery for the affected 256-, 384-, and 512-bit Lynxer relations, and report accepted fresh-message forgeries. Their separate Lynx-192 analysis concerns another upstream variant and does not extend this finding to the archived NGCC 160-bit sets.

On 2026-09-29 the Lynxer team also [released a targeted modification note](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3HMAZXK7HD6JDLF5BJVYWDECM2SF5N3M/) for its later revision, not the archived Round 1 package tested here.

### Proposed fixes

The [Lynxer team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TJ3HPFROBMZMNMEHDEC3IQRO7R7QHQAQ/) proposes replacing the original S-boxes with inversion as described in [ePrint 2026/1099](https://eprint.iacr.org/2026/1099). Its later [targeted-modification note](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3HMAZXK7HD6JDLF5BJVYWDECM2SF5N3M/) describes an additional proposal for the revised construction. This section records the proposals without evaluating them.

### Reproducing

```sh
make -C sign-14 exploit-public-forgery
```

The wrapper checks out the pinned public reproducer, verifies the official source-archive hash, compiles against the archived reference code, and runs all six positive and changed-message controls. It requires Git, curl, unzip, and a C compiler.

## sign-14-2: A shared TCCR tweak enables one-signature multi-target key recovery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Lynxer-256s/f, -384s/f, and -512s/f; the 160-bit sets remain above their 128-bit target
Discovery: Moderate
Exploitation: About 2^248.2, 2^375.6, and 2^503.2 TCCR evaluations from one signature
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UG3RQWO5YK7WWMXM5KRTAE457PKIAI62/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/fffffb85983e71188430446f526ede3a211aded0/lynxer-bavc-tccr-multitarget)
Follow-up source: [Lynxer team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LI25TET2FFYRZPAZQLLQAYHDN7V7NGOJ/)

Within one BAVC tree, every expansion uses the same `(s,iv)` tweak; the bit entering `TCCR` selects an output block, not a node position (reference `tccr.c:13–55`, `bavc.c:50–64`; optimized `prgs.hpp:494–540`). The non-padding nodes published in `decom_I`, at most `T_open`, are therefore simultaneous targets for one enumeration of a hidden parent. A hit reconstructs the hidden leaf, `u_0`, the witness, and its first `lambda` bits—the OWF signing key. This contradicts the single-target argument in §8.2.2 (physical pp. 68–69); the construction and opening are specified in §§5.4.1 (p. 34) and 5.9.8 (p. 51).

For a signature containing `T` actual targets this costs about `2^lambda/(T+1)`. The `T_open` maxima give optimistic thresholds near `2^248.2`, `2^375.6`, and `2^503.2`; a concrete transcript must use its actual target count. Each candidate parent changes the TCCR key `x_R||iv`, so a candidate test costs about one key schedule and one block-cipher call (§5.9.8, physical p. 51). The pinned package checks the tree relations and separately demonstrates a scaled key recovery and fresh-message forgery by targeting the public leaf commitments. The full-width tree-node enumeration is a theoretical below-target attack, not a practical forgery demonstration; its costs miss the 256-, 384-, and 512-bit claims, hence Critical. For the 160-bit profiles the analogous cost is about `2^153`, above the NGCC 128-bit target but below Lynxer's stated 160-bit aim (§6.1, physical p. 53).

### Proposed fixes

The Lynxer team proposes redefining the tweaks as node-index tweaks. Xiong and Wang's [follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MMFK7Z4EON66VU7Z3DCJ4QGVFDWMRYCB/) additionally proposes making the node index an actual TCCR input. These proposals are recorded without evaluating them.

### Reproducing

```sh
./sign-14/reproduce_tccr_multitarget.sh
```

## sign-14-3: Fixed leaf-commitment tweaks enable multi-target key recovery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Lynxer-256s/f, -384s/f, and -512s/f; the 160-bit sets remain above their 128-bit target
Discovery: Moderate
Exploitation: About 2^251.5/2^250.9, 2^378.9/2^378.3, and 2^506.5/2^505.8 evaluations for the s/f profiles
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance; leaf-commitment extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UG3RQWO5YK7WWMXM5KRTAE457PKIAI62/), [leaf-index follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MMFK7Z4EON66VU7Z3DCJ4QGVFDWMRYCB/), and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/fffffb85983e71188430446f526ede3a211aded0/lynxer-bavc-tccr-multitarget)

The independent leaf commitment discards any node identity and calls `prg_2_lambda(seed,iv,0)` for every leaf (`bavc.c:85–91,142–150`; archived optimized `vector_com.inc:1090–1115`). One signature publishes a hidden-leaf commitment for each of `tau` VOLE instances (§5.4.7, physical p. 38; §8.2.3, physical p. 69). An enumeration can therefore test each candidate against all `tau` public commitments at once. A hit reconstructs the hidden leaf; the public correction values then give `u_0` and the witness, whose first `lambda` bits are the signing key.

The resulting cost is about `2^lambda/tau`, below the 256-, 384-, and 512-bit claims by about 4.5–6.2 bits. The leaf commitment is computed by a separate PRG call, not by the TCCR tree expansion, so this route does not depend on the tree's TCCR tweak. For the 160-bit profiles the cost is about `2^156`, above the NGCC 128-bit target but below Lynxer's stated 160-bit aim (§6.1, physical p. 53). No full-width search was run.

### Proposed fixes

Xiong and Wang propose including the leaf index in `LeafHash`. This records the proposal without evaluating it.

### Reproducing

```sh
./sign-14/reproduce_tccr_multitarget.sh
```

The scaled run searches against the public hidden-leaf commitment, recovers the key, and forges. The `1/tau` full-size multi-target accounting is a counting certificate.

## sign-14-4: The quantum EUF-CMA proof misses every target through its TCCR error term

Severity: High
Status: Proof gap
Layer: Design
Affected: Lynxer-160/256/384/512 S/F
Discovery: Moderate
Exploitation: At one signing query the submitted bound gives about 22, 117, 116, and 244 proof-error bits against 80-, 128-, 192-, and 256-bit quantum targets; no attack follows
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-05

Theorem 9.13 (physical p. 115) includes a quantum TCCR term `O(D/2^(lambda-n))`, independent of the attacker's work, where `n` is the block size: 128 for the 160/256-bit profiles and 256 for the 384/512-bit profiles (Table 7, physical p. 57). Lemma 9.11 (physical pp. 91–92) uses `D=(2 ceil(log2 L)+5) tau`, doubles the TCCR advantage, and multiplies by the number of commitments. Theorem 9.5 (physical pp. 92–93) sets that number to the signing-query count `Q_sig`.

Ignoring the hidden constant, this contributes about `2 Q_sig D/2^(lambda-n)` to the quantum EUF-CMA bound. At `Q_sig=1` its negative base-two logarithm is 22.1/21.7, 117.3/116.9, 116.6/116.3, and 244.2/243.8 bits for the s/f profiles. All miss their target, and the term grows with signatures. These are proof-error exponents, not attack costs. The bound is not shown tight, and this finding demonstrates no forgery or key recovery.

### Reproducing

```sh
python3 sign-14/reproduce_quantum_tccr_bound.py
```

## sign-14-5: The 160-bit sets add the first Lynx constant to both S-box inputs

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Lynxer-160s and Lynxer-160f; reference and optimized implementations
Discovery: Trivial
Exploitation: The implemented one-way function differs from the specified one, and a signer or verifier written from the specification does not interoperate; no attack shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance, in this candidate's specification notes of 2026-09-21; independently reported by Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, using MechCrypto
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/digital-signature/sign-14_Lynxer)

Lynx is specified as `v1 = S1(k + c1)` and `v2 = S2(L0(k) + c2)` (Eq. 5 and 6, physical p. 22). `Lynx.SampleMatVec` derives `c1` and `c2` as two separate slices of the expanded `iv_owf` (§5.5.1, physical p. 39), and `Lynx.ExtendWitness` adds `c2` to `L0·k` for λ = 160 (§5.5.2 line 4, physical p. 40).

The 160-bit code never uses the second constant. `owf_lynx_160` loads only `mats.C0` and computes `v1 = S1(k + c0)` and `v2 = S2(L0k + c0)` (`owf.c:600–605`). The witness extension does the same (`owf.c:763–766`), and the QuickSilver prover and verifier for λ = 160 load only `C0` (`quicksilver.c:335,396`). `lynx_init` still squeezes both constants (`lynx_matrices.c:484–485`), so `C1` is generated and discarded. The paths for 256, 384 and 512 bits use `C0` for the first S-box and `C1` for the second (`owf.c:654–661`). The optimized tree makes the same choice and says so in a comment, "160-bit: S2 uses c0 (same as S1)" (`lynx_owf.hpp:50–51`).

Key generation, signing and verification in the submitted code agree with each other, and the KATs were produced by this function. An implementation of the specified Lynx-160 computes a different public value `t` from the same `(iv_owf, k)` and cannot verify the submitted signatures. The two S-box inputs share one constant where the design has two independent ones; no consequence for one-wayness was derived. The specification states `c2` in three places, so this is a conflict and not a misprint.

### Reproducing

```sh
sed -n '600,605p' sign-14/Implementations/Reference_Implementation/Lynxer-160f/owf.c
grep -n -A1 '160-bit: S2 uses c0' sign-14/Implementations/Optimized_Implementation/Lynxer-160f/lynx_owf.hpp
```

This is a source witness.

## sign-14-6: The sampled linear layers are read with the wrong row stride, which puts Lynxer-160 key recovery at about 2^141.5

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Lynxer-160s/f (key recovery below the design level); Lynxer-256s/f and Lynxer-384s/f (rank loss, no attack below target); reference and optimized implementations; Lynxer-512s/f are unaffected
Discovery: Non-trivial
Exploitation: Key recovery from the public key in about 2^141.5 bit operations at Lynxer-160: 2^100 guesses, each solved by degree-3 XL, run at full size for the correct guess on two keys; below the specified 160-bit level, above the 128-bit NGCC target; no route below target at 256 or 384 bits
Credit: Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, with MechCrypto assistance; rank measurement and key-recovery route by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/digital-signature/sign-14_Lynxer)

The specification samples `L0`, `L1` and `L2` as invertible λ×λ binary matrices (footnote 4, physical p. 23; physical p. 60). `lynx_init` stores them in `uint64_t L[512][8]`, eight words per row (`lynx_matrices.h:15–23`), but the one-way function and the QuickSilver constraints read them with ⌈λ/64⌉ words per row (`owf.c:595–597,648–650,678–680`; `quicksilver.c:325–327,786–788,1038–1040`). Only λ = 512 is read as stored; `L3` is copied in contiguously. The optimized tree and the KATs share the behaviour (`owf_proof.inc:169–182`). As read, the matrices have rank 100 of 160, 128 of 256 and 382 to 384 of 384, and adding a kernel vector of `L0` to the key leaves the second S-box output `v2` unchanged.

At λ = 160 this gives a key-recovery route. Guessing `u = L0(k)`, one of 2^100 values, fixes `v2 = S2(u + c0)` and `L2(v2)`, so the output `y = L1(v1)·L2(v2) + L3(k + v1 + v2)` is linear in `(k, v1)` and leaves 60 unknowns. The inverse S-box `v1 = (k + c0)^-1` gives the relations `x·v1 = 1`, `x²v1 = x`, `xv1² = v1`, `x⁴v1 = x³` and `xv1⁴ = v1³` with `x = k + c0`: 800 quadratic equations, which plain XL solves at degree 3. On two keys from the submitted code, the correct guess solved to the secret key in 2^35.5 word operations, about 14 seconds, and a wrong guess was inconsistent. The total is about 2^141.5 bit operations, against the specified 160-bit level and the 2^184.6 of Table 14 (physical p. 63). The guess-and-determine argument (physical p. 64) assumes that guessing an S-box input costs 2^λ.

The route stays above the NGCC target for this set, 128 bits classical; a Grover search over the guesses with a degree-2 oracle is estimated at about 2^85.6 gates, against 80 bits quantum. At λ = 256 the 2^128 guesses leave 384 unknowns because of the `(k + c2)^-1` factor, and no per-guess solver below 2^128 was found. The 2^100 enumeration was not run.

### Reproducing

```sh
sh sign-14/reproduce_matrix_stride.sh
sh sign-14/reproduce_lynx160_key_recovery.sh
```

The first script measures the ranks in Lynxer-160f, -256f, -384f and -512f built from the unmodified sources, and checks the invariance of `v2` through the exported `lynx_extend_witness` (about 30 seconds). The second builds the submitted Lynxer-160f code and the XL solver `sign-14/reproduce_lynx160_xl.c`, solves the system for the correct guess from the public key, and requires the secret key, the same `y`, and rejection of a wrong guess (about 35 seconds per seed; OpenMP and BMI2).
