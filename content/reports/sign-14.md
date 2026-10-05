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

Within one BAVC tree, every expansion uses the same `(s,iv)` tweak; the bit entering `TCCR` selects an output block, not a node position (`tccr.c:13–55`, `bavc.c:50–64`). The non-padding nodes published in `decom_I`, at most `T_open`, are therefore simultaneous targets for one enumeration of a hidden parent. A hit reconstructs the hidden leaf, `u_0`, the witness, and its first `lambda` bits—the OWF signing key. This contradicts the single-target argument in §8.2.2 (physical pp. 68–69); the construction and opening are specified in §§5.4.1 and 5.9.8.

For a signature containing `T` actual targets this costs about `2^lambda/(T+1)`. The `T_open` maxima give optimistic thresholds near `2^248.2`, `2^375.6`, and `2^503.2`; a concrete transcript must use its actual target count. The pinned package checks the tree relations and, separately, demonstrates a scaled key recovery and fresh-message forgery through the leaf-commitment route described below. The full-width tree-node enumeration is a theoretical below-target attack, not a practical forgery demonstration.

### Proposed fixes

The Lynxer team proposes redefining the tweaks as node-index tweaks. Xiong and Wang's [follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MMFK7Z4EON66VU7Z3DCJ4QGVFDWMRYCB/) additionally proposes making the node index an actual TCCR input. These proposals are recorded without evaluating them.

### Reproducing

```sh
./sign-14/reproduce_tccr_multitarget.sh
```

## sign-14-3: Fixed leaf-commitment tweaks give a second multi-target key-recovery route

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Lynxer-256s/f, -384s/f, and -512s/f; the 160-bit sets remain above their 128-bit target
Discovery: Moderate
Exploitation: About 2^251.5/2^250.9, 2^378.9/2^378.3, and 2^506.5/2^505.8 evaluations for the s/f profiles
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance; leaf-commitment extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UG3RQWO5YK7WWMXM5KRTAE457PKIAI62/), [leaf-index follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MMFK7Z4EON66VU7Z3DCJ4QGVFDWMRYCB/), and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/fffffb85983e71188430446f526ede3a211aded0/lynxer-bavc-tccr-multitarget)

The independent leaf commitment discards any node identity and calls `prg_2_lambda(seed,iv,0)` for every leaf (`bavc.c:85–91,142–150`). One signature publishes a hidden-leaf commitment for each of `tau` VOLE instances. An enumeration can therefore test each candidate against all `tau` public commitments at once. A hit reconstructs the hidden leaf; the public correction values then give `u_0` and the witness, whose first `lambda` bits are the signing key.

The resulting cost is about `2^lambda/tau`, below the 256-, 384-, and 512-bit claims by about 4.5–6.2 bits. This route remains if only the internal TCCR nodes are retweaked; the leaf PRG also needs instance or leaf separation. No full-width search was run.

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

Theorem 9.13 (physical p. 115) includes a quantum TCCR term `O(D/2^(lambda-n))`, independent of the attacker's work. Lemma 9.11 (physical pp. 90–92) uses `D=(2 ceil(log2 L)+5) tau`, doubles the TCCR advantage, and multiplies by the number of commitments. Theorem 9.5 (physical pp. 92–93) sets that number to the signing-query count `Q_sig`.

Ignoring the hidden constant, this contributes about `2 Q_sig D/2^(lambda-n)` to the quantum EUF-CMA bound. At `Q_sig=1` its negative base-two logarithm is 22.1/21.7, 117.3/116.9, 116.6/116.3, and 244.2/243.8 bits for the s/f profiles. All miss their target, and the term grows with signatures. These are proof-error exponents, not attack costs. The bound is not shown tight, and this finding demonstrates no forgery or key recovery.

### Reproducing

```sh
python3 sign-14/reproduce_quantum_tccr_bound.py
```
