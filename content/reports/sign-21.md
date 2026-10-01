<!-- synchronized report: sign-21/report.md -->
Candidate: ReSolveD-α
Family: Code-based (regular syndrome decoding, VOLE-in-the-head)
Archive: [ReSolveD-alpha.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/ReSolveD-alpha.zip) (SHA-256: `499821538d7f79464cc1ee1468254b0e49f750794a591ffe038938c4cfa11914`)

## sign-21-1: A shared TCCR tweak enables one-signature multi-target key recovery below the claimed levels

Severity: Critical
Status: Confirmed
Layer: Design
Affected: ReSolveD-α-256s/f, -384s/f, and -512s/f; reference and optimized implementations
Discovery: Moderate
Exploitation: One signature; about 2^248.2, 2^375.6, or 2^503.2 TCCR evaluations for full signing-key recovery and forgery
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PH6Q6UHS7YJAN3RHER7YWUNXOHOZYIFF/)
Follow-up source: [ReSolveD-α team's acknowledgment of receipt](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/WI3PDQ3FGAT6H7TSKV4STFL5X6WCZEQF/)

`BAVC.Commit` expands every internal node of one signature with the same TCCR parameters `(s, iv)`. The reference code passes no node position to `tccr_hash` (`bavc.c:50–69`, `tccr.c:13–51`); the optimized AES and Rijndael paths likewise compute the node position but do not pass it into TCCR (`prgs.hpp:494–516`; the generic fallback is at 521–540). The output-block byte inside TCCR is not a tree-node tweak. A signature reveals `T` sibling nodes, each a public function of a different hidden parent under this one TCCR instance.

An attacker enumerates a parent candidate once and tests its derived child values against all `T` revealed nodes with a hash table. A match identifies a hidden subtree, from which the attacker derives the hidden leaf, reconstructs the complete witness, and signs a fresh message. The expected search is `2^lambda/(T+1)`: median `T` values of 221/217, 330/328, and 437/439 for the small/fast 256-, 384-, and 512-bit sets give about 2^248.2, 2^375.6, and 2^503.2 evaluations. The target mapping is recorded in the archived `Algorithm specifications Addition.pdf`, Table 24; the 160-bit sets target 128 bits and remain above that target.

This directly contradicts §7.1.2's conclusion that no multi-target attack improves on a single target. A fresh `iv` separates different signatures, not the hundreds of targets inside one signature; the specification's own Theorem 8.12 includes a multi-target term proportional to the number of construction queries under a fixed tweak. Each affected set therefore has a concrete classical signing-key recovery bound below its claimed level, hence Critical. The full exponential search was not run, but source/specification reasoning and scaled searches establish the `/T` speedup, the recovery chain, and accepted fresh-message forgeries.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PH6Q6UHS7YJAN3RHER7YWUNXOHOZYIFF/) proposes adding a node-index/instance tweak to TCCR and the leaf PRG, or increasing `lambda` by `ceil(log2(T_open)) + 1` bits and removing the single-target claim. This section records those proposals without evaluating them.

### Reproducing

```sh
sh sign-21/reproduce_tccr_multitarget.sh
```

The pinned [reproduction package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/5568023b43000ce9eb38467705bb2731f230c73b/resolved-alpha-tccr-multitarget) builds against the archived reference source with the Keccak backend. It checks the tree relation on real signatures. To make enumeration feasible, its scaled experiment is given all but 20–22 bits of one selected hidden parent, tests every candidate against the complete revealed-node table, finds the selected target, reconstructs the witness from the public transcript, and produces a fresh-message forgery accepted by the unmodified verifier; a one-bit-witness control rejects. It does not demonstrate an unconstrained search in which any revealed node is equally reachable. A separate experiment confirms constant-work hash-table membership and the predicted `2^B/(T+1)` scaling. Only the final `2^248.2` or larger enumeration is extrapolated.
