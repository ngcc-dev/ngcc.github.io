<!-- synchronized report: sign-29/report.md -->
Candidate: Tins
Family: Multivariate (MPC-in-the-head)
Archive: [Tins.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Tins.zip) (SHA-256: `84affc1f7cbdeec48a7cb6df3349b5708644672f2ac12140c529e74f6d57ca21`)

Tins was withdrawn on 2026-09-25. These findings evaluate the frozen submitted artifact and remain in the historical record.

## sign-29-1: One signature reveals the complete signing witness

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Tins128, Tins256, and Tins512
Discovery: Non-trivial
Exploitation: One signature and binary Gaussian elimination on at most 1,044 unknowns
Credit: Tianyuan Xie
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ECMH3PMGM2NWJG4JIBQBCKQ6U5CBUDDA/)
Follow-up source: [Tins team's 2026-09-25 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AJF5VVYQAJTICBWFFS5DHIO4U2FZZOXT/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §16](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

Tianyuan Xie reported the attack in the [NGCC PKC Forum](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ECMH3PMGM2NWJG4JIBQBCKQ6U5CBUDDA/). Tins masks its binary witness `(alpha,beta)` with vectors over the 12-bit subfield, while publishing `p_mid` in `GF(2^k)`. After substituting the verifier-reconstructed evaluations into `p_mid`, the bilinear witness terms cancel in characteristic two. Only a 12-bit additive mask remains, confined to the final subfield coefficient.

Every execution therefore exposes `k-12` public binary equations in the `2(n-2)` witness bits. Two executions from one signature have full rank for each submitted set: the reported ranks after the first and second executions are 264 then 276, 516 then 532, and 1,032 then 1,044. Recovering the witness is deterministic and inexpensive; the witness satisfies the public NSBC relation and can run the specified signer on arbitrary messages, violating EUF-CMA.

The local reproducer independently performs the attack on a fresh Tins128 key and signature. It uses only the public key and signature after signing, obtains rank 276/276 from two executions, and validates the recovered witness against the public relation. Xie additionally reports end-to-end accepted forgeries on all three sets and exact recovery from all ten usable Tins128 and Tins256 KAT signatures.

On 2026-09-25, the Tins team [confirmed Xie's attack and withdrew the proposal](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AJF5VVYQAJTICBWFFS5DHIO4U2FZZOXT/). They said sampling the masking polynomial over the smaller subfield had been a known design risk chosen for efficiency.

### Reproducing

```sh
make -C sign-29 exploit
```

## sign-29-2: Deterministic TINS expansion depends on the external DRBG

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Tins128, Tins256 and Tins512 reference implementations
Discovery: Trivial
Exploitation: Public-key expansion and transcript generation depend on the particular external RBG stream; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

TINS resets local external DRBG contexts from the public and secret seeds during key generation, signing and verification (`SIG_TINS256.c:57–58,167–168,380`). BAVC commitment and challenge expansion does the same (`bavc_commit.c:339,485,573`). Since the verifier must reconstruct identical values, the exact ICCS DRBG stream is an unstated part of the signature format.

The archived implementation interoperates with itself. The Low defect is the use of an external RBG as a protocol PRG; these expansions should use a specified XOF.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id sign-29-2
```

## sign-29-3: Unchecked signature length overflows the verifier's path buffer

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Tins128, Tins256 and Tins512 reference, optimized and additional verifiers
Discovery: Trivial
Exploitation: An oversized untrusted signature causes an attacker-sized stack overwrite before verification; no control-flow exploit was attempted
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/BZPZIT2TNBMEG7CPGNOUELVXPYUAQTDZ/)

`sig_verify` derives `path_size = (sn_len_bytes - NTemp) / NODE_SIZE` without checking either bound, then copies `NODE_SIZE * path_size` bytes into fixed `node path[T_OPEN]` (current reference `SIG_TINS128.c:350–365`; analogous code in the other tiers). An oversized supplied signature writes beyond that stack array; a short signature can underflow the unsigned subtraction or be read before this point. We independently reproduced a 3,140-byte write into Tins128's 2,500-byte `path` with AddressSanitizer. This is attacker-controlled memory corruption, not merely a build failure; code execution has not been shown.

### Reproducing

```sh
python3 sign-29/reproduce_implementation_findings.py --report-id sign-29-3
sh sign-29/reproduce_path_overflow.sh
```

The first command checks the current SHA-256-pinned ZIP's bounds and copy. The second rebuilds that ZIP and checks a normal-length control and the oversized-signature write under AddressSanitizer; it needs a C compiler and archive download unless `TINS_ARCHIVE` points to a local copy.

## sign-29-4: Tins128 compares its challenge with an uninitialized buffer

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Tins128 reference, optimized and additional verifiers in the current submitted ZIP
Discovery: Trivial
Exploitation: Challenge consistency depends on uninitialized stack contents; honest-verification failure is reproduced, but a fresh-message forgery is not independently established
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/BZPZIT2TNBMEG7CPGNOUELVXPYUAQTDZ/)

The current ZIP sets `LAMBDA=160`, making `hash_t` 40 bytes, but Tins128 signing hashes only 256 bits (`SIG_TINS128.c:288`). Verification declares `test_h_piop`, recomputes into `h_piop` instead, and compares all 40 bytes against the uninitialized `test_h_piop` (`:414,430–436`). A separate-process gcc build rejected an honest signature in our check. The post reports changed-message acceptance on its clang build; our clang build did not reproduce that result, so no forgery is claimed here. The local extracted Tins128 tree predates the ZIP version cited in this report.

### Reproducing

```sh
python3 sign-29/reproduce_implementation_findings.py --report-id sign-29-4
```

## sign-29-5: Tins512 verification overwrites the supplied signature

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Tins512 reference, optimized and additional verifiers
Discovery: Trivial
Exploitation: Verification reads uninitialized auxiliary data and can reject honest signatures; no forgery is shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/BZPZIT2TNBMEG7CPGNOUELVXPYUAQTDZ/)

Signing copies compressed auxiliary data from `stmp` into `sn`. Verification repeats that copy direction rather than reading from `sn` into `stmp` (`SIG_TINS512.c:325,328,379–382`). It overwrites the caller's signature with mostly uninitialized stack bytes and decodes those bytes. The post's fresh-process tests reject all 20 honest signatures under both tested compilers; our certificate establishes the source defect, not that rate. This is a correctness and availability failure in the submitted verifier.

### Reproducing

```sh
python3 sign-29/reproduce_implementation_findings.py --report-id sign-29-5
```

## sign-29-6: An odd challenge count writes past Tins512's stack array

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Tins512 reference, optimized and additional signing and verification
Discovery: Trivial
Exploitation: Every honest signing attempt writes four bytes past a stack array; AddressSanitizer aborts, but no further impact is demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/BZPZIT2TNBMEG7CPGNOUELVXPYUAQTDZ/)

Tins512 has `TAU=47`. `ExpandChallengePoint` loops while `2*i < TAU` but writes both indices `2*i` and `2*i+1` (`bavc_commit.c:497–521`). At `i=23`, the second write is `challenge_points[47]`, past the 47-element caller array. We reproduced the honest-signing stack-buffer-overflow under AddressSanitizer; the normal build's effect depends on stack layout. A following odd-tail branch does not undo the write.

### Reproducing

```sh
python3 sign-29/reproduce_implementation_findings.py --report-id sign-29-6
```

## sign-29-7: Public-salt GGM expansion exposes the complete signing witness

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Tins128, Tins256 and Tins512 reference, optimized and additional implementations; end-to-end forgery reproduced on Tins256 reference
Discovery: Moderate
Exploitation: One signature, public mask reconstruction, and a fresh-message forgery; no exponential search
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

The specification defines `ChildrenNodesGen(salt, seed, idx)` as expansion from a parent `seed` (physical p. 11). Every submitted `ChildNodeGen` implementation accepts that parent parameter but constructs both child seeds solely from the public `salt` and node index (`bavc_commit.c:108–124`). The root `rseed` is therefore irrelevant below the root: anyone knowing the salt can reconstruct every GGM leaf. `CommitPoly` derives the per-leaf mask streams from `salt || leaf` and publishes `aux[e] = (alpha,beta) XOR mask[e]` in the signature (`bavc_commit.c:329–406`). Recomputing the mask with a zero witness and arbitrary root, then XORing it with the decoded public `aux`, reveals the actual `(alpha,beta)` in every repetition.

Against the submitted Tins256 reference code, the local witness recovered one common `(alpha,beta)` in all 24 repetitions from one signature and checked it against the true signing witness. It then supplied only that recovered witness and the public key seed to the submitted signer through a linker wrapper around its two witness draws. A signature on a fresh message passed the unmodified Tins256 verifier; the same signature failed on a changed message. The wrapper only substitutes the recovered witness in signing and passes all verifier calls through unchanged. Whole-scheme forgery was tested at Tins256; the all-tier claim is limited to the source-level mask exposure.

### Reproducing

```sh
python3 sign-29/certify_public_tree_source.py
sh sign-29/reproduce_public_tree_witness.sh
```

The source certificate checks all nine local implementation trees. Pass `--archive /path/to/Tins.zip` to check the SHA-256-pinned submitted archive as well. The runtime witness compiles the submitted Tins256 reference sources into a temporary directory; no candidate source is patched.
