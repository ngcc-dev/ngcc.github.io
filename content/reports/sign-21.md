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
Follow-up source: [ReSolveD-α team's acknowledgment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/WI3PDQ3FGAT6H7TSKV4STFL5X6WCZEQF/), [initial confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GEDCFLSHBQTVSIW5K7ACXWGY7GKOXASI/), and [gate-count response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LENFP6BEMJ3FLXKLKGXM4GGTCAC4IAKU/); [Xiong and Wang's reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PIHDF2YFZDOURZJXDI5USKT6KPGTAFC2/)

`BAVC.Commit` expands every internal node of one signature with the same TCCR parameters `(s, iv)`. The reference code passes no node position to `tccr_hash` (`bavc.c:50–69`, `tccr.c:13–51`); the optimized AES and Rijndael paths likewise compute the node position but do not pass it into TCCR (`prgs.hpp:494–516`; the generic fallback is at 521–540). The output-block byte inside TCCR is not a tree-node tweak. A signature reveals `T` sibling nodes, each a public function of a different hidden parent under this one TCCR instance.

An attacker enumerates a parent candidate once and tests its derived child values against all `T` revealed nodes with a hash table. A match identifies a hidden subtree, from which the attacker derives the hidden leaf, reconstructs the complete witness, and signs a fresh message. The expected search is `2^lambda/(T+1)`: median `T` values of 221/217, 330/328, and 437/439 for the small/fast 256-, 384-, and 512-bit sets give about 2^248.2, 2^375.6, and 2^503.2 evaluations. The target mapping is recorded in the archived `Algorithm specifications Addition.pdf`, Table 24; the 160-bit sets target 128 bits and remain above that target.

This directly contradicts §7.1.2's conclusion that no multi-target attack improves on a single target. A fresh `iv` separates different signatures, not the hundreds of targets inside one signature; the specification's own Theorem 8.12 includes a multi-target term proportional to the number of construction queries under a fixed tweak. Each affected set therefore has a concrete classical signing-key recovery bound below its claimed level, hence Critical. The full exponential search was not run, but source/specification reasoning and scaled searches establish the `/T` speedup, the recovery chain, and accepted fresh-message forgeries. The ReSolveD-α team confirms that the missing per-node tweak is a specification bug.

The team later gave a gate-count analysis and Xiong and Wang confirmed its
arithmetic under that model. Their `2^247.66` figure for the 256-bit set uses
the maximum target count and 50% success; the `2^248.2` figure above uses the
median target count and expected work. This approximately half-bit difference
is only a convention. The classification counts attacks in the
specification's own units. §5.1 bounds a coin-enumeration forgery by an
expected work of `2^lambda` trials. §5.2, although headed "Selection of RSD
Parameters", converts the target into gates by charging `lambda^2.3` per
symmetric-key operation and requiring `(lambda + 2.3 log lambda)`-bit
security, about `2^274.4` gates at `lambda = 256`. Charging roughly two
block-cipher operations per TCCR test gives about `2^248.66` operations at the
256-bit level, still about 7.3 bits below the `2^256` trial count, and the
team's `2^262.6`-gate estimate likewise falls below the specification's
gate-equivalent target. Adding a circuit cost only to the attack while leaving
the target in evaluations mixes units; converting both sides preserves the
multi-target advantage. This is a certificational shortfall, not a practical
attack. It shares its root cause, the absence of a per-node tweak, and its
fix with the leaf-commitment multi-target loss; the two are recorded
separately because they refute different claims (§7.1.2 and §7.1.3). Multi-instance PPRF losses and instance-specific tweaks in
MPC-in-the-head signatures are discussed in [Bui et al., ePrint
2024/252](https://eprint.iacr.org/2024/252).

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PH6Q6UHS7YJAN3RHER7YWUNXOHOZYIFF/) proposes adding a node-index/instance tweak to TCCR and the leaf PRG, or increasing `lambda` by `ceil(log2(T_open)) + 1` bits and removing the single-target claim. The [team response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GEDCFLSHBQTVSIW5K7ACXWGY7GKOXASI/) proposes node-index tweaks as in FAEST v2. This section records those proposals without evaluating them.

### Reproducing

```sh
sh sign-21/reproduce_tccr_multitarget.sh
```

The pinned [reproduction package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/5568023b43000ce9eb38467705bb2731f230c73b/resolved-alpha-tccr-multitarget) builds against the archived reference source with the Keccak backend. It checks the tree relation on real signatures. To make enumeration feasible, its scaled experiment is given all but 20–22 bits of one selected hidden parent, tests every candidate against the complete revealed-node table, finds the selected target, reconstructs the witness from the public transcript, and produces a fresh-message forgery accepted by the unmodified verifier; a one-bit-witness control rejects. It does not demonstrate an unconstrained search in which any revealed node is equally reachable. A separate experiment confirms constant-work hash-table membership and the predicted `2^B/(T+1)` scaling. Only the final `2^248.2` or larger enumeration is extrapolated.

## sign-21-2: A shared leaf-commitment tweak gives one-signature multi-target key recovery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: ReSolveD-α-256s/f, -384s/f, and -512s/f; reference and optimized implementations
Discovery: Moderate
Exploitation: One signature; about 2^250.87, 2^378.27, or 2^505.83 leaf-PRG evaluations for witness recovery and forgery
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's original PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PH6Q6UHS7YJAN3RHER7YWUNXOHOZYIFF/)
Follow-up source: [Xiong and Wang's clarification](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TU4TWGKTQ46F5HCMMRX25XMKVQG7JPEX/)

The specified `LeafHash(x,iv)` uses the fixed tweak `0^8` (§4.4.7), while
`BAVC.Open` publishes one hidden-leaf commitment per instance (§4.4.2,
Algorithm 14, line 18). This contradicts §7.1.3 (p. 63), which treats the PRG
calls as separated by distinct counters. The reference code uses zero for every
leaf (`bavc.c:85–90,141–150`). The optimized leaf-hash wrapper discards both
provided tweaks (`vector_com.inc:1090–1097`); its 160/256-bit path supplies zero
(`vector_com.inc:1102–1107`), while its 384/512-bit paths use fixed-tweak
helpers (`vector_com.inc:1112–1115`, `prgs.hpp:2022–2055,2242–2299`).

An attacker enumerates one candidate seed, evaluates the fixed-tweak leaf PRG
once, and tests its commitment against every revealed hidden-leaf target.

With `tau` targets, expected work is about `2^lambda/tau`. The submitted
parameters therefore give exponents 251.5/250.9, 378.9/378.3 and 506.5/505.8
for the small/fast 256-, 384- and 512-bit profiles, respectively. A match
completes one VOLE instance; the public correction then reconstructs the
masked regular-syndrome-decoding witness and permits a fresh-message forgery.
Table 24 of the addition specification maps the 160-bit profiles to a 128-bit
target; their approximately 156-bit costs remain above it.

This is a complete mathematical recovery route below each affected target,
although the final exponential enumeration was not run. A repair that changes
only internal tree-node expansion does not separate `LeafHash`; the leaf PRG
requires its own instance-specific domain input.

The team's later [gate-count response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LENFP6BEMJ3FLXKLKGXM4GGTCAC4IAKU/)
prices each candidate test as a circuit, and [Xiong and Wang](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PIHDF2YFZDOURZJXDI5USKT6KPGTAFC2/)
confirm that arithmetic under the stated model. The response uses maximum
`tau` and 50% success, giving `2^250.33` leaf evaluations at the 256-bit level;
the `2^250.87` value above uses the report's expected-work convention.
Counting primitive evaluations as in §5.1, and charging roughly two
block-cipher operations per test, the attack remains roughly 4–5 bits below
the claimed level. In gates, the team's `2^265.26` estimate also falls below
the `(lambda + 2.3 log lambda)`-bit target that §5.2 applies, about `2^274.4`
gates at `lambda = 256`. Applying the per-test implementation cost
consistently to attack and baseline does not remove the multi-target factor.
This too is a certificational result; no full-width enumeration was attempted.
It shares its root cause, the absence of a per-node tweak, and its fix with
the TCCR multi-target loss; the two are recorded separately because they
refute different claims (§7.1.3 and §7.1.2). See [Bui et
al., ePrint 2024/252](https://eprint.iacr.org/2024/252) for the corresponding
multi-instance PPRF concern and per-instance tweaking in MPC-in-the-head
signatures.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PH6Q6UHS7YJAN3RHER7YWUNXOHOZYIFF/)
proposes assigning every leaf-PRG invocation a node/instance tweak, as in
FAEST v2. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 sign-21/reproduce_leaf_commitment_multitarget.py
```

The certificate checks the fixed zero tweak in every submitted reference and
optimized profile and recomputes the multi-target bounds. It explicitly
records that the full exponential search is not executed.

## sign-21-3: Same-key cross-profile access is outside EUF-CMA despite reproduced witness recovery

Severity: Info
Status: Confirmed
Layer: Design
Affected: ReSolveD-α-160/256/384/512 S/F pairs in the optional deterministic mode permitted by the specification
Discovery: Moderate
Exploitation: Outside the evaluated model: two same-message signatures from distinct profiles sharing a key in the optional deterministic mode recover an equivalent witness and permit forgery
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-01
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HNQWNWEIP44QKJGMBCNRQIZCRHDLIAZC/) and [pinned attack package](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/d0db6e0e0a28ef7ef41fe5dd826aa17ff743bcba/ReSolveD-alpha)
Follow-up source: [ReSolveD-α team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TE3JLRXYSLPJUTFXC34R5NF7QIAZIQIB/)

ReSolveD-α permits optional deterministic signing by setting `rho = 0^lambda`
(§4.2.2 and §4.9.2); the default path samples `rho` randomly. At each level the
S and F profiles share the key format and RSD relation, while `CoinHash` binds
the secret seed, message digest and `rho` but not the profile
(`voleith_impl.c:167–184`). Consequently, same-key same-message S/F signatures
using that optional mode reuse the root seed and IV under different tree shapes.

The complementary openings recover a hidden leaf, complete the corresponding
VOLE transcript, and reveal an equivalent RSD witness through the public
correction. The reproduced 160-bit attack uses that witness to create a
fresh-message signature accepted by the untouched verifier; different-key,
different-message and different-`rho` controls reject. The submitted API's
ordinary randomized signing path samples fresh `rho` and is not affected
unless randomness repeats.

This conditional composition is outside the isolated single-profile EUF-CMA
experiment: it requires one key to be installed in two profiles and use of an
optional non-default signing mode. The reproduced recovery therefore confirms
the behavior but not an attack on either profile's claimed game, hence Info.
Key reuse across cryptographic contexts is a recognized composition question,
but requires a joint-security model; see Patton and Shrimpton, [*Security in
the Presence of Key Reuse*](https://eprint.iacr.org/2019/519).

The team replies that keys should be generated independently for S and F, that
randomized signing is the intended operational mode, and that deterministic
signing is for implementation checking. The frozen specification nevertheless
expressly defines deterministic signing in §4.2.2 and §4.9.2. The Info
classification rests on cross-profile same-key access being outside EUF-CMA,
not on treating the specified deterministic option as nonexistent. Feussner's
[follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/K3QX7GB7RL5CPG7NUQ3BXO37PLCRI2YU/)
likewise states that the result does not break ordinary single-profile
EUF-CMA.

### Reproducing

```sh
sh sign-21/reproduce_cross_profile_recovery.sh
```

The wrapper downloads the commit- and hash-pinned package and builds its
minimal reproducer. The paired-signature generator uses the package's
documented `CoinHash` patch; final acceptance is checked by a binary linked to
the untouched submitted verifier. The wrapper requires recovery, an accepted
fresh-message forgery, and all negative controls.
