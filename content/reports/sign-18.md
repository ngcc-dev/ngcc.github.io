<!-- synchronized report: sign-18/report.md -->
Candidate: Origami
Family: Multivariate (layered MQ)
Archive: [Origami.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Origami.zip) (SHA-256: `e34f18832e968681dd0c51ce0d4b29d80e01ad29daa83dfb805718b76fdffa80`)

## sign-18-1: A fixed 512-bit message prehash caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Origami-384 and Origami-512 specifications, reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Origami-384 and Origami-512 claim 384- and 512-bit classical security but first compress every message with the same fixed 64-byte `H_msg`. They only then derive the randomized target from `target || H_msg(message) || salt`.

A generic collision in `H_msg` costs about `2^256` evaluations. Once two messages share that prehash, every later salt produces the same signing target for both, so a signature requested on one message transfers to the other. Adding the salt after the short prehash does not repair the collision.

The construction and length are explicit in both the PDF and source, making this a specification-level design break of both advertised classical EUF-CMA levels.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-18-1
```

The check verifies physical PDF pages 14–16 and 50–52 and the submitted 64-byte digest constant.

## sign-18-2: Signatures expose the hidden-algebra constraint subspace

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All four parameter sets
Discovery: Moderate
Exploitation: Polynomial-time structure recovery; no complete forgery demonstrated
Credit: Peigen Li (archive sender `PeigenLi`)
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/7LD2222NOYVSL3KXW4UQCLPHMU7JFKQW/)

Additional reference: [Louiso, Guo, Li, Pébereau, Tao, and Ding, ePrint 2026/2390](https://eprint.iacr.org/2026/2390)

The specification places every vinegar and oil element in a degree-`l_j` subalgebra of `l_j`-by-`l_j` matrices, but counts and solves all `l_j^2` matrix coordinates independently. These requirements are incompatible: a subalgebra element has only `l_j` degrees of freedom. The implementation makes the signer work by sampling only vinegar elements in the hidden subalgebra while treating oil coordinates as unrestricted field elements, contradicting the specified variable space.

Peigen Li's [mailing-list analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/7LD2222NOYVSL3KXW4UQCLPHMU7JFKQW/) identifies this mismatch and observes that repeated signatures reveal the small hidden subalgebras. Further extension to Peigen Li's analysis: the source gives Origami-128 exactly 18 sampled degree-2 vinegar elements; each occupies four matrix coordinates but has dimension two. Every signature therefore lies in a subspace of dimension at most `200 - 18*(4-2) = 164`. A run of 180 accepted signatures reaches rank 164, saturating that bound, while 180 uniform 200-coordinate vectors reach the sample-count maximum rank 180. The analogous source count predicts 180, 336, and 432 exposed constraints for Origami-256, -384, and -512.

This is direct, reproducible leakage of the purportedly hidden structure, but no end-to-end key recovery or forgery is yet established. The post's separate estimate of at most 93 bits for Origami-128 has no published derivation and is therefore not adopted here.

The follow-up paper formalizes the dimensional mismatch and records the same 164-dimensional Origami-128 bound. It distinguishes this signature-derived leakage from its public-key-only forgery: the forgery does not require signatures or recovery of the hidden subalgebras, so it does not strengthen this finding's exploitation claim.

### Reproducing

```sh
make -C sign-18 lib/libOrigami-128.so
python3 sign-18/reproduce_signature_subspace.py
```

The witness verifies every collected signature with the official verifier before measuring its rank over `GF(16)`.

## sign-18-3: Variable-time hidden-zone linear solving

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Origami reference signer, all four parameter sets
Discovery: Trivial
Exploitation: Local timing/cache side channel; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Signing builds a linear system from the expanded secret zone structure and sampled hidden variables, then solves it with first-nonzero pivot search and data-dependent row skips. The reference `origami_ref.c` branches on matrix entries at lines 636 and 659, and on the solve result at line 798. Thus a local trace can distinguish properties of intermediate private systems. This does not by itself establish recovery of the master seed or a forgery; see `constant_time.md` for the secret/public classification.

Constant-time fix (moderate, hence Medium): use constant-time Gaussian elimination that adds candidate pivot rows under masks, a well-known technique in constant-time UOV and MAYO implementations. It processes every row at every step, a moderate cost; a retry on a singular system is the usual accepted exception.

### Reproducing

In each reference instance, follow `sign` → `build_zone_system` → `solve_rect_random` in `origami_ref.c`; inspect the pivot test and early break at lines 633–640, row skip at 659, and attempt retry at 794–811. This is a source/dataflow witness, not a measured remote timing exploit.

## sign-18-4: Signing indexes field tables and signature state with private values

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Origami reference signer, all four parameter sets
Discovery: Trivial
Exploitation: Local cache/address trace of secret intermediates; forgery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Origami's `gf_mult` and `gf_inv` index 256-byte and 16-byte tables by field operands (`origami_gf.h:25,32-37`), including private central-map and solver values during signing (`origami_ref.c:400,599-601,653-661`). The signer also derives `w_vars` from private permutation `rho` and writes `secret_y[w_vars[i]]` (`origami_ref.c:421-426,798-800`). These addresses can depend on private values even for the same public message. No measured cache channel or EUF-CMA forgery is established; see `constant_time.md`.

Constant-time fix (easy, hence Low): replace the `gf_mult`/`gf_inv` tables with table-free or `pshufb`-based GF(2^8) arithmetic, and write `secret_y` through a masked scan over all positions instead of indexing it by the private permutation. The scan costs about n^2 byte operations for n variables, small next to signing.

### Reproducing

Inspect the cited lookup definitions and signer call sites in `Implementations and Test_Vectors/Implementations/Reference_Implementation/Origami-256/`; the same pattern is present in the other reference parameter sets. This is a source/dataflow witness, not a measured extraction.

## sign-18-5: Public variable permutation permits signature forgery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Origami-128, Origami-256, Origami-384, and Origami-512; independently reproduced here on Origami-128
Discovery: Moderate
Exploitation: Public-key-only forgery for a chosen message, with no signing queries
Credit: Hugo Louiso, Hao Guo, Peigen Li, Pierre Pébereau, Siyong Tao, and Jintai Ding
Date: 2026-09-24
Original source: [Ding and Louiso's NIST PQC Forum post](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/N1WfpgvlI2s/m/lym34vPOAwAJ), [Pébereau's NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HTZTMJ42AUXCWEDA3AURP4ZOEGSGSV4Z/), and [UnfoldOrigami code](https://github.com/pi-r2/UnfoldOrigami/tree/defa3405d66e763580729b14d6f81c1300fbb219)

Additional reference: [Louiso, Guo, Li, Pébereau, Tao, and Ding, ePrint 2026/2390](https://eprint.iacr.org/2026/2390), with [all-level C reproduction code](https://github.com/hlouiso/origami-forgery); [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §4](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

Origami §2.5.6 explicitly derives the change of variables `Π_pub` from the *public* expansion seed and defines `P_pub = G ∘ Π_pub^-1`. Undoing that permutation exposes the zone order. The public-key expansion supplies each zone's affine coefficients, so an attacker can choose its vinegar coordinates and solve the resulting linear system for oil coordinates, proceeding zone by zone. This reproduces the signer's easy inversion without its secret seed or a signing oracle. It is distinct from `sign-18-2`'s signature-derived subspace observation.

The consolidated paper records that the authors disclosed the attack to the Origami designers on 2026-09-22 and announced it publicly on both the NIST PQC Forum and the NGCC PKC Forum on 2026-09-24, together with the Origami-128 SageMath implementation. It identifies the attack in both announcements as the exposed-layer construction analyzed in the paper. We accept that documented timeline and joint attribution.

The paper also supplies an independent C implementation covering all four sets. Across 384 random-key/message trials, all 384 public-key-only forgeries were accepted by the unmodified reference verifier, while signature, salt, and message mutations all rejected. Fresh builds reproduced the official KATs, and a distinct forgery was accepted for every KAT key and message. Mean forgery times were 0.0107, 0.577, 2.73, and 5.16 seconds from Origami-128 through Origami-512. These are the authors' experiments; our pinned local replay remains the Origami-128 SageMath implementation described below.

Our pinned replay of Pébereau's code forges on Origami-128 against the archived `sig_verify`, and a changed-message control rejects. We have not executed a forgery on Origami-256, -384, or -512 ourselves. Their inclusion in `Affected` rests on the paper's all-level C runs and on the identical public-permutation construction in the four submitted sources, not on a local all-level replay.

The four submitted sets have byte-identical `origami_ref.c` evaluators and the same public-permutation construction. The flaw survives ideal replacement of the contest hash/XOF placeholders: whatever public expansion is used, the public `seed_pk` still determines `Π_pub`, so anyone can undo it and expose the triangular zone system.

The paper further shows that the submission's MT-MQ Assumption 7 fails in its independent-coefficient model: a sequential public inversion pass succeeds with probability above 0.93 for every submitted set. This proof analysis supports the same public-map forgery and does not require a separate finding ID.

### Reproducing

```sh
make -C sign-18 lib/libOrigami-128.so
T=$(mktemp -d)
git clone https://github.com/pi-r2/UnfoldOrigami.git "$T/UnfoldOrigami"
git -C "$T/UnfoldOrigami" checkout defa3405d66e763580729b14d6f81c1300fbb219
python3 sign-18/reproduce_public_forgery.py "$T/UnfoldOrigami"
```

The local checker verifies SHA-256 `1fe0c4ca114efd217a1e42291f60450dd3a4edd2606b8ef56e411ebc46594917` for `forge.sage` and `b287be01bf244ca7cdc749b2bb7c9ca00d756e0eee895bb117d5f722352e9cb2` for `technical.py` before importing the pinned attack code. It loads only the library built from the archived Origami source, not the repository's bundled binary. It seeds key generation afresh, erases the resulting secret before calling `forge`, verifies the new signature, and rejects the same signature on a changed message. Three local runs passed with roughly 0.6-second inversion each; this is not an all-level benchmark. Python must provide `hashlib` SM3 support for this submitted evaluation variant.

## sign-18-6: The tail-zone retry loop repeats an unchanged singular system

Severity: Low
Status: Confirmed
Layer: Design
Affected: All four parameter sets in the specification and both implementation families
Discovery: Moderate
Exploitation: Honest signing aborts measured at 6.45–6.67% for Origami-128; the same mechanism affects all sets; no forgery or key recovery
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; mechanism and independent measurements by Hugo Louiso, Hao Guo, Peigen Li, Pierre Pébereau, Siyong Tao, and Jintai Ding
Date: 2026-10-06
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MP3WUOWQBA4SJ6TFEZYS62D6OE56K3L7/)

Additional reference: [Louiso, Guo, Li, Pébereau, Tao, and Ding, ePrint 2026/2390, §7](https://eprint.iacr.org/2026/2390)

The final tail zone has eight equations and eight solved coordinates, but no vinegar or sampled coordinates. If its `8 × 8` matrix over `GF(16)` is singular, the specification's repeat loop cannot change that matrix. Algorithm 4 nevertheless repeats until the local solve succeeds (physical p. 26), while §4.5 and Table 13 incorrectly treat the 8192 attempts as independent and claim final abort probabilities below `2^-33482` through `2^-45245` (physical pp. 54–55).

The submitted signer resamples nothing in the tail and runs the same solve 8192 times before returning an error (`origami_ref.c:769–818`). The reference and optimized core files are byte-identical across all four sets. Under the paper's uniform-tail-matrix heuristic, a random `8 × 8` matrix over `GF(16)` is singular with probability about 6.6%; uniformity of the generated matrices is not proved. The original post observed 213 aborts in 3300 Origami-128 calls and aborts at all four optimized levels. The follow-up paper observed 20/300 and 9/80 aborts at Origami-128 and -256 and traced every one to the tail.

Our broader unmodified Origami-128 replay obtained 19 natural aborts in 199 calls, with the other 180 signatures accepted by the submitted verifier. This confirms an honest-signing correctness and availability defect, not a cryptographic attack.

### Reproducing

```sh
make -C sign-18 lib/libOrigami-128.so
python3 sign-18/reproduce_tail_abort.py
```

The deterministic witness pins one naturally aborting call and one successful verified control, using ordinary messages and fresh per-call salts. It does not force a singular system or patch the signer.
