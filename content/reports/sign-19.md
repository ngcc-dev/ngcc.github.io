<!-- synchronized report: sign-19/report.md -->
Candidate: Phoenix
Family: Hash-based signature
Archive: [Phoenix.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Phoenix.zip) (SHA-256: `ec801791976a10baffa852c479afd12362af3b5fb6420104254fb48814d99918`)

## sign-19-1: Phoenix parameter sets define incompatible signature languages

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference/AVX2 pairs SHAKE-128f, SHAKE-128s, SHAKE-192f, and SM3-192s
Discovery: Trivial
Exploitation: Official implementations reject otherwise valid signatures from the same named parameter set
Credit: Qin Zhen
Date: 2026-09-29
Original source: [Qin's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3B6IDLJHSE7TD4NACBIGRT4H3JKRPR7J/)

The specification gives no numeric `SPX_TFORS_SIG_MAX`: Algorithm 19 (physical PDF page 35) requires the transmitted TFORS length to equal the length computed from Octopus pruning. The submitted reference and AVX2 trees instead assign different upper bounds to four identically named parameter sets: respectively 2156/2436, 1716/1732, 5372/5396, and 5274/5298 bytes. The reference verifier enforces its extra upper bound at `sign.c:54`, while the AVX2 signer can emit signatures beyond it. Thus the reference implementation is the non-conforming side of the cross-implementation rejection.

For Phoenix-SHAKE-128f, both submitted implementations reproduce their own ten-record KATs and self-verify. The reference signatures are 13,610–13,658 bytes and the AVX2 signatures 13,722–13,946 bytes; the latter also exceed the specification's advertised 13,668-byte Phoenix-SHAKE-128f size. The AVX2 verifier accepts all ten shorter reference signatures, but the reference verifier rejects all ten AVX2 signatures. A fresh rebuild reproduces record zero exactly: 13,658 versus 13,882 bytes, with the same key and message, and the reference verifier rejects the optimized signature.

This is an implementation-level interoperability defect; no forgery or key recovery is demonstrated, hence Low.

### Reproducing

```sh
python3 sign-19/reproduce_interop.py
```

The script builds both submitted Phoenix-SHAKE-128f implementations in a temporary directory, reproduces the first KAT seed and message, checks both self-verification controls, and prints `CONFIRMED sign-19-1` after the asymmetric cross-verification result.

## sign-19-2: SHAKE-384f AVX2 can exceed its declared signature buffer

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Phoenix-SHAKE-384f-avx2 signing
Discovery: Moderate
Exploitation: Some honest signatures write two bytes past a buffer allocated using `sig_get_sn_len_bytes`; no further impact is shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HVWF4FETH3YWXDV4F42FLWEDB47XINMU/)

The AVX2 `SPX_BYTES` maximum omits the two-byte TFORS-length prefix that the signer writes (`params/params-phoenix-shake-384f.h:74`; `SIG_AlgorithmInstance.c:65,228,454–456`). The 384f TFORS maximum is reachable exactly, so those signatures total 88,442 bytes against the declared 88,440. The post observed 9/3,752 and 3/1,756 such signatures and an AddressSanitizer heap overwrite; our certificate checks the submitted size arithmetic, not that frequency. Other SHAKE AVX2 tiers retain a margin because their TFORS maxima are not multiples of `SPX_N`. This is a bounded memory-safety defect, not a forgery.

### Reproducing

```sh
python3 sign-19/reproduce_avx2_findings.py --report-id sign-19-2
```

## sign-19-3: AVX2 SM3 chain and tree hashes omit the public seed

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: All ten Phoenix-SM3 AVX2 parameter sets
Discovery: Moderate
Exploitation: Per-key hash separation specified for the tweakable hashes is absent; no complete forgery or security-bit loss has been established
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HVWF4FETH3YWXDV4F42FLWEDB47XINMU/)

Phoenix's tweakable hashes take `PK.seed` as an input (specification physical pp. 9–10). The reference SM3 `thash` and `prf_addr` continue from a state pre-absorbing that seed (`Reference_Implementation/Phoenix-SM3-512s/thash_sm3_simple.c:13–27`). AVX2 instead hashes `ADRS || input` or `ADRS || SK.seed` directly; its copied seeded state is unused (`Optimized_Implementation/avx2/Phoenix-SM3-512s-avx2/thash_sm3_simple.c:13–27`, `hash_sm3.c:21–32`). The certificate checks the scalar path; the x4/x8 paths are source-inspected but not part of its assertions. Thus the chain/tree hashes and address PRF are no longer separated by public key. Other uses of `PK.seed`, including message hashing, remain. The consequence for full signature security is unresolved, so no numerical attack claim is made.

### Reproducing

```sh
python3 sign-19/reproduce_avx2_findings.py --report-id sign-19-3
```

## sign-19-4: A 256-bit SM3 prehash caps message-retargeting security

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Phoenix-SM3-384s/f and -512s/f, reference and AVX2 implementations
Discovery: Moderate
Exploitation: One signing query and approximately 2^256 SM3 evaluations for a fixed-target second preimage; the full exponential search was not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

Phoenix appends a public counter to the message before `H_msg`. In each affected implementation, `hash_message` first computes a 32-byte SM3 digest of `R || PK || M || counter`, then expands that digest with MGF1-SM3 (reference `Phoenix-SM3-512s/hash_sm3.c:106–165`) or `sm3_xof` (AVX2 `Phoenix-SM3-512s-avx2/hash_sm3.c:100–159`). Although the expanded output is longer, every message-dependent challenge bit is determined by this 256-bit intermediate value. The signer writes `R` and the selected counter into the signature; the verifier reads both and hashes the supplied message with those same values (`sign.c:173–195,280–294` in the reference tree, with corresponding AVX2 calls).

Given a signature on `M`, an attacker fixes its public `R`, public key, and counter, then searches for a distinct `M'` with the same inner SM3 digest. A generic fixed-target second-preimage search costs about `2^256` evaluations. The expanded digest, tree and leaf indices, and all later verification checks are then identical, so the original signature verifies on `M'`. This is below the 384- and 512-bit classical claims. The cost is a *second-preimage* bound: the message-dependent `R` prevents using a pre-signing birthday collision to claim `2^128` work.

### Reproducing

```sh
python3 sign-19/certify_sm3_prehash.py
```

The certificate checks the four affected parameter sets in both submitted implementation families. It verifies the 32-byte intermediate, its expansion, and the signer/verifier reuse of the serialized `R` and counter; it does not execute a `2^256` search.

## sign-19-5: Every high-level SM3 signature exposes part of `SK.prf`

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Phoenix-SM3-384s/f and -512s/f, reference and AVX2 implementations
Discovery: Moderate
Exploitation: One ordinary signature discloses 16 of 48 `SK.prf` bytes at 384 or 32 of 64 at 512; no signing-key recovery or forgery from this disclosure is shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

`gen_message_random` computes HMAC-SM3 in a 96-byte local `buf`. The final `sm3(buf, buf, 96)` writes only its 32-byte digest at the start of that buffer. Bytes 32 through `SPX_N−1` still contain the HMAC outer pad, `SK.prf[i] XOR 0x5c`, because the code immediately copies `SPX_N` bytes of `buf` into the public signature randomizer `R` (reference `Phoenix-SM3-512s/hash_sm3.c:82–98`; AVX2 `Phoenix-SM3-512s-avx2/hash_sm3.c:76–92`). Thus a signer using either 48- or 64-byte `SPX_N` publishes those secret-key bytes in every signature. This read stays inside the allocated buffer and does not depend on stack layout.

The certificate obtained valid signatures accepted by the submitted reference verifiers at all four affected sets and matched all 16 leaked bytes at each 384-bit set and all 32 at each 512-bit set. The remaining `SK.prf` bytes, `SK.seed`, and a full forgery were not recovered. This is a direct partial secret-key disclosure, not a full signing-key recovery.

### Reproducing

```sh
python3 sign-19/reproduce_sm3_prf_disclosure.py
```

The script builds and uses all four submitted reference libraries, then prints only match counts, not secret material.

## sign-19-6: Reference high-level SM3 hashes copy past their digest buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Phoenix-SM3-384s/f and -512s/f reference implementations
Discovery: Trivial
Exploitation: The hash helpers read 16 or 32 bytes beyond a 32-byte stack digest; a reviewed build copied digest-state bytes, with no secret disclosure shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

The reference `thash`, `thash_fin` and `prf_addr` helpers allocate a 32-byte SM3 output buffer and then copy `SPX_N` bytes from it (`Phoenix-SM3-512s/thash_sm3_simple.c:16–27,47–76`; `hash_sm3.c:20–37`). `SPX_N` is 48 bytes at the 384-bit level and 64 at the 512-bit level. The extra bytes are read from adjacent stack storage. Another local in these helpers is the completed SM3 state; in a reviewed build the copied excess duplicated digest-state bytes, not a secret. Stack layout is compiler-dependent, so that observation does not make the over-read safe in every build. The AVX2 helpers use an output-length-aware XOF instead, and the lower reference levels have `SPX_N≤32`.

This is a source-confirmed out-of-bounds read on normal hash-helper calls. No secret disclosure, independently reproduced sanitizer trace, forgery or key recovery is demonstrated; Low reflects that evidence boundary.

### Reproducing

```sh
python3 sign-19/certify_sm3_digest_overread.py
```

The certificate checks the digest and copy sizes in all four affected reference trees; it does not execute a signer.

## sign-19-7: The index sampler can run out of randomness, and the failure is ignored

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Phoenix-384s (about 2^-27.6 per message digest) and 384f (2^-35.3); 128f, 192s and 256f at 2^-63 or less; SHAKE and SM3, reference and AVX2 implementations
Discovery: Moderate
Exploitation: A digest for which the sampler fails makes signing and verification continue with uninitialised index values; such digests cost about 2^28 hash evaluations to find for 384s. No forgery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Phoenix derives part of each TFORS index set with `h2_generate_indices`. The function expands the message digest to a fixed 512-byte pool, takes eight bytes per sample, and collects distinct values until it has enough. When the 64 samples are used up it returns −1 (`hash_shake.c:102,112,130`; the SM3 trees are the same). Its only caller, `message_to_indices`, ignores the return value and reads the local array `indices1[]` regardless (`tfors.c:55–73`).

For Phoenix-384s the sampler needs 27 distinct values out of 64, and 64 uniform draws from 64 values fall short with probability 2^-27.6. For 384f the figure is 2^-35.3. In a search over 1.12×10^9 digests the archived 384s sampler failed seven times; the witness replays one such digest.

On failure the indices are whatever the stack held. An honest signer meets this about once in 2^27.6 messages and then opens TFORS leaves at positions that are not bound to the message. A verifier can be driven into the same path by a signature whose randomizer, counter and message were chosen to hit a failing digest. We did not turn this into a forgery; the positional part of each index is still computed from the digest. The consequence is unresolved, hence Medium.

### Reproducing

```sh
sh sign-19/reproduce_h2_exhaustion.sh
```

The witness checks the pool, the failure return and the unchecked call in the reference SHAKE and SM3 384s trees. It then builds the archived Phoenix-SHAKE-384s sampler and requires −1 for one concrete digest and 0 for a neighbouring control. The failure probabilities are exact occupancy calculations and are not recomputed by the witness.

## sign-19-8: SM3 fixed points extend any signed message under its own signature

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Phoenix-SM3-256s/f, -384s/f and -512s/f, and -192s/f when the signed messages are long; reference and AVX2 implementations
Discovery: Moderate
Exploitation: A forgery that reuses one of q collected signatures costs about 2^256/q inverse SM3 compressions, 2^192 at the 2^64 signatures of one key, and about 2^172 if those signatures are on 64 MiB messages; both attacks shown end to end on a 20-bit model, and the full searches were not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-23

Reference: [Guo, Cheng, Preneel and Wang, *Provable Security of SHA-256-Based LMS Revisited in the Ideal-Cipher Model*, ePrint 2026/2624](https://eprint.iacr.org/2026/2624), §3.2; [Strenzke, *A Kelsey–Kohno Attack Variant against SHA-2 Message Digests in HSS/LMS and XMSS*, ePrint 2026/2635](https://eprint.iacr.org/2026/2635), §3.2

Phoenix claims its full security level for up to 2^64 signatures per key (physical pp. 4–5). The SM3 sets hash a message as `seed = SM3(R ‖ PK.seed ‖ PK.root ‖ M ‖ counter)` and expand `R ‖ PK.seed ‖ seed` into the digest and indices (reference `hash_sm3.c:141,151,160`; AVX2 `:135,145,154`). The verifier takes `R` and the 4-byte counter from the signature (`sign.c:282–291`). The per-signature `R` is meant to stop one search from serving many signatures.

The candidate's SM3 (`sm3_drng.c`) is a plain Merkle–Damgård hash. Its digest is the last chaining value, and its compression function is `V' = E_B(V) ⊕ V` with `E_B` invertible for every block `B`. So for any chosen `B`, the value `S = E_B^-1(0)` is a fixed point: compressing `B` from `S` gives `S` again.

Collect q signatures and their seeds. Choose a final block `B = D ‖ padding`, where `D` is 51 free bytes followed by a 4-byte counter, and compute `S`. If `S` equals the seed of signature i, then the message `M_i ‖ counter_i ‖ pad ‖ D[0..50]`, with the SM3 padding of the signed input as message bytes and the counter taken from the end of `D`, has the same seed under the same `R_i`. The expansion then has the same inputs, so signature i verifies for the longer message once its counter field is replaced. Shorter signed inputs are reached by repeating `B`, which a fixed point allows. The forged input extends the target's own input, so differing `R` values do not separate the targets, and each trial succeeds with probability q/2^256.

At q = 2^64 the cost is about 2^192 inverse compressions and a table of 2^64 seeds, below the 256-, 384- and 512-bit claims. The 128- and 192-bit sets use the same 32-byte seed, and this attack does not put them below their targets at 2^64 signatures.

Long signed messages lower the cost, because every intermediate chaining state of a signed message is then a target. Strenzke's hourglass attack first uses collisions to merge into one state the states that follow each signature's `R ‖ PK` prefix, with chosen message bytes filling the prefix's last block. A 256-bit state allows this for about 2^164 compressions at 2^64 signatures. An expandable message built from a fixed point then lets one search link into any intermediate state of any signed message, and the rest of that message is copied, so `R`, the length and the counter are unchanged. For 2^k1 signatures on messages of 2^k2 blocks the cost is about `2^(132 + k1/2) + 2^129 + 2^(256 − k1 − k2)` compressions (Equation (4)): 2^172.0 for 2^64 signatures on 64 MiB messages and 2^166.3 on 4 GiB messages. That is also below the 192-bit sets' claim. The paper states these costs for SHA-256, which has the same state width, block size and compression structure as SM3.

### Reproducing

```sh
python3 sign-19/reproduce_sm3_fixed_point.py
```

The witness checks the sixteen source trees, checks an independent SM3 against the standard test vectors, and confirms that `E_B^-1(0)` is a fixed point for 64 padding-compatible blocks and that the forged input reduces to one compression call on the seed. It then runs both attacks on a Davies–Meyer hash with a 20-bit state and the same layout. The fixed-point attack forges four of 64 signed inputs with distinct `R` at about the expected 2^20/64 trials each. The hourglass attack merges 16 long signed inputs into one state and forges three of them, each keeping its `R`, public key, length and counter.
