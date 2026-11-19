<!-- synchronized report: sign-02/report.md -->
Candidate: BiT
Family: Lattice-based
Archive: [BiT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip) (SHA-256: `698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d`)

## sign-02-1: A 512-bit unsalted message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-512 specification, reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [BiT team's 2026-10-12 PKC Forum update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ONSUXJ3MD4PYXHBRPIVGKBXW5CZ7ONIT/)

BiT-512 claims 512-bit classical security and normatively computes the message representative `mu = H(tr || M)` as a 512-bit value. This fixed unsalted representative has only 256 bits of generic collision resistance.

After finding distinct messages with the same `mu`, an attacker requests a signature on one and transfers it unchanged to the other. Later signing randomness cannot distinguish the already-colliding messages. The reference implementation uses the same 64-byte representative.

This is a specification-level design break of the advertised 512-bit classical EUF-CMA level. It is a generic `2^256` security ceiling, not a computation performed by the harness.

### Proposed fixes

The team reports revising BiT-512 to bind the message and its encoded length directly into the Fiat–Shamir challenge, instead of a fixed-length prehash. It points to [revised materials](https://light-lattice.org/bit/). This proposal is recorded without evaluating the revision.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-02-1
```

The check verifies the normative BiT-512 construction on physical PDF pages 18 and 33–34 and the 64-byte source constant.

## sign-02-2: A shared bimodal sign leaks an equivalent BiT-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-128; the same shared-sign construction appears in the other sets, but their recovery costs were not established
Discovery: Non-trivial
Exploitation: Equivalent-key recovery from 200,000 public signatures and a fresh-message forgery accepted by the unmodified verifier; a changed-message control rejects
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/84_EKMOtk_M/m/ZNMqLQ07BAAJ)
Follow-up source: [BiT team's 2026-10-12 PKC Forum update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ONSUXJ3MD4PYXHBRPIVGKBXW5CZ7ONIT/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §8](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

BiT uses one hidden sign for the entire response, but its rejection rule corrects each coefficient against a *scalar* mixture. The joint response remains a mixture of two product distributions and retains secret-dependent cross-coordinate correlations even when the individual marginals have the intended distribution. The response to the known constant component gives an observation of the common sign, allowing the remaining response components to reveal the signing secret statistically. Figures 2 and 4 specify a single sign bit per signature with coefficientwise rejection; §3.1.3’s assertion that “z is independent of b” fails for the joint response. The reference source has the same pattern (`sign.c:134–153`, `sample.c:124–259`). The mechanism does not depend on a hash weakness.

The released public-transcript attack streams 200,000 signatures from an ordinary signing oracle, statistically recovers a candidate key, repairs low-confidence coefficients by a public search when the candidate fails the compressed public-key relation (in our run, 1,596 candidates over 24 search bits), completes an equivalent key that satisfies the relation, and produces a fresh-message signature accepted by the unmodified BiT-128 verifier. A changed-message control rejects. We reproduced its fixed key-0 experiment in 164 CPU-seconds on a single-threaded `Intel Core Processor (Broadwell, IBRS)` validation VM; the attack never reads or compares the generated secret key. This upgrades the finding from Probable to Confirmed. The authors report three of four fixed keys succeeding at 200,000 signatures and the fourth at 250,000; no success-rate claim beyond those experiments is made.

Follow-up analysis: the [BiT team's 2026-09-29 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/74QWBAYF4KZYN5HDHM2ROENQUDVWAUGT/) confirms this shared-sign issue and says that the distinct compressed-public-key leakage reported for CS also applies to the earlier BiT version. No BiT-specific derivation, transcript, or witness for that second route accompanied the response. Since the confirmed shared-sign route already yields equivalent-key recovery and forgery, the additional statement is retained as follow-up evidence rather than assigned a separate vulnerability ID.

### Proposed fixes

The team reports replacing coefficientwise rejection with a parabolic rejection sampler over the full response vector, and transmitting the complete public key instead of compressing it. It presents these as responses to the shared-sign and compression routes, respectively. The revision is recorded without evaluation.

### Reproducing

```sh
sign-02/reproduce_bimodal_key_recovery.sh
```

The wrapper downloads and hash-checks both Feussner's [attack package at commit `91f2ddf`](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/91f2ddf0590a24ad39afc2ce2ee4f2627ec54726/BiT) and the official BiT submission archive. It runs the fixed 200,000-signature key-0 experiment and requires equivalent-key recovery, fresh-message acceptance and changed-message rejection.

## sign-02-3: Mask-seed collisions recover an equivalent BiT-128 signing key

Severity: Critical
Status: Probable
Layer: Design
Affected: BiT-128 specification, reference and AVX2 implementations; BiT-256 and BiT-512 use 256- and 512-bit mask seeds and are not affected within the query budget
Discovery: Moderate
Exploitation: Equivalent-key recovery and an accepted fresh-message forgery from publicly detected seed collisions in a reduced-width (16- and 24-bit) seed build of the submitted code; the full 128-bit birthday search was not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Figure 5 (physical p. 19) derives all signing masks from `seed_y ∈ {0,1}^κ := XOF(ρ′ || rnd || µ)`, with κ = 128 for BiT-128. The reference code squeezes `BIT_SEEDBYTES = 16` bytes (`sign.c:99–103`, `params.h:47`), and every mask and rejection coin of a signing call is then expanded from `(seed_y, nonce_y)` (`sample.c:20–25`); the AVX2 tree is the same (`sign.c:101–102`). Two signing calls on different messages that draw the same `seed_y` therefore draw the same sequence of masks `y`, and they return the same `y` whenever their rejection histories coincide. The bimodal sign bit `b` comes separately from the DRBG.

For such a pair, `z_{1,0} = y_0 + (−1)^b c` and `z_{1,1} = y_1 + (−1)^b s_0 c` (`sign.c:148–151`) give `d_0 = z_{1,0} − z′_{1,0} = (−1)^b c − (−1)^{b′} c′` and `z_{1,1} − z′_{1,1} = s_0 · d_0` exactly in `Z_q[X]/(X^n+1)`. A negacyclic linear solve gives `s_0`, and the remaining key material `(e′, b_0′)` follows from the public relation `A_0 s_0 − γ_B b_1 = b_0 − e`. The result is an equivalent signing key. The pairs are found from public data alone: equal `y` gives an equal verifier commitment `w′` (`sign.c:260–262`), so sorting signatures by `w′` finds them.

About 0.22 of seed collisions are usable (112 completed keys from 512 expected collisions, measured in the reduced-width build). Among Q signatures the expected number of usable pairs is therefore about `0.22 · Q²/2^129`. This gives about 10.3% attack success at the mandatory `2^64` signatures per key, 50% success at about `2^65.33` signatures, one expected usable pair at about `2^65.60`, and about `2^28.8` usable pairs at the `2^80` signing-query budget. Sorting the commitments costs about `2^66` time and memory. Theorem 2 (physical p. 24) treats `y` as fresh per signature; its loss term contains no `q_S² · 2^−κ` term for repeated mask seeds. The result is equivalent-key recovery and universal forgery against BiT-128 below its 128-bit EUF-CMA and SUF-CMA target.

The experiment changes only the width of `seed_y`. With 16 bits kept, 8,192 ordinary signatures on distinct messages gave 112 public commitment matches, and all 112 completed equivalent keys. The recovered `s_0` equalled the oracle key, and a fresh-message signature made with the equivalent key was accepted by the unmodified verifier. The shipped 128-bit build produced no match on the same key and DRBG stream, a non-matching pair fails completion, and the changed-message control rejects. The `2^64`-scale collision search itself was not run, so the status is Probable. The equivalent key has a short `e′` consistent with the public key, not the original `e`, but the signatures it produces verify.

### Reproducing

```sh
sh sign-02/reproduce_seed_collision.sh
NGCC_LONG=1 sh sign-02/reproduce_seed_collision.sh
```

The script copies the BiT-128 reference tree to a temporary directory, inserts the seed truncation directly after `seed_y` is squeezed, builds a 16-bit and an unmodified variant, and runs the public collision search, completion and forgery on 8,192 signatures each (about 25 seconds). It requires every match to complete an equivalent key, the forgery to verify, the changed message and a non-matching pair to reject, and the full-width control to find no match. `NGCC_LONG=1` uses 24 bits and 65,536 signatures (about 2.5 minutes).

## sign-02-4: BiT-512 hint bytes have several accepted encodings

Severity: High
Status: Confirmed
Layer: Implementation
Affected: BiT-512 reference and AVX2 implementations; BiT-128 and BiT-256 pack hints differently and were not checked for this
Discovery: Moderate
Exploitation: From one signature, byte-distinct signatures on the same message that the verifier accepts; no new message is signed and no key is recovered
Credit: Xifeng Jin (CertiK), with AI assistance
Date: 2026-11-16
Original source: [Jin's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/F4GNQLORBJWXMMKZWFGTLOT7GRTRKXYI/)

Each BiT-512 hint polynomial has 1,024 ternary coefficients, packed five per byte as a base-3 number (`packing.c:104–125`, `params.h:53–58`). 1,024 is not a multiple of five, so the last of the 205 bytes holds four coefficients and an unused fifth digit, which the packer sets to 1. The unpacker stops at coefficient 1,024 without examining that digit (`packing.c:127–162`), and the verifier does not compare the decoded signature with a canonical re-encoding (`sign.c:234–269`). Any of the three values of the unused digit therefore gives the same signature. Complete groups have a second alias: a byte holds five base-3 digits, values up to 242, and the unpacker discards the quotient left after five divisions, so bytes 243–255 decode like 0–12.

With the archived reference code, we rewrote the last hint byte of each of the three hint polynomials with each value of its unused digit. All nine verified for the signed message, and six differ from the original signature. Adding 243 to a complete-group byte of value at most 12 also verified. Every variant was rejected for a different message. The AVX2 source has the same packer and unpacker.

The specification claims strong unforgeability (SUF-CMA, §5.1, Theorem 2, p. 23), which a second accepted encoding of a queried signature contradicts.

### Reproducing

```sh
sh sign-02/reproduce_hint_aliases.sh
```

The witness checks the packer and unpacker in the reference and AVX2 trees, signs one message with the reference build, and requires the nine final-byte variants and one complete-group alias to verify for that message, six of them byte-distinct, and every variant to be rejected for another message.

## sign-02-5: A failed digest allocation leaves the previous digest in the verifier

Severity: High
Status: Confirmed
Layer: Implementation
Affected: BiT-128, -256 and -512; reference and AVX2 implementations (identical by source; the witness runs the reference)
Discovery: Moderate
Exploitation: If a digest allocation fails after an earlier verification in the same process, a signature on the earlier message verifies for a new message; at BiT-128 only messages longer than 4,064 bytes allocate
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; challenge-hash route by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5V3E3JF4EVSU3KCFBH6HKUBRXNDSQI6O/)

Verification hashes `tr ‖ m` into a message digest and later recomputes the challenge from it (Fig. 5, physical p. 19, Verify lines 4 and 8). In BiT-128, `crypto_sign_verify` declares `message_hash` on the stack without initialising it (`sign.c:223`) and fills it with the `void` helper `bit_h256_2` (`:250`). Inputs over 4,096 bytes are copied into `malloc(total)`, and the helper returns without writing when that allocation fails (`symmetric.c:50–51`). BiT-256 and -512 use `bit_h512_2`, which returns the same way (`symmetric.c:88–89`) and also casts the `pseudohash` status to `void` on both paths (`:92,97`); `pseudohash` returns before writing when its own copies fail. The recomputed challenge, `bit_h512(c_prime, …)` (`sign.c:265`), discards the same status.

With the reference code at all three levels, a signature on message A was accepted for a different message B when the targeted allocation failed during the verification of B, immediately after verifying A in the same process. Without the failure, or with the stack scrubbed between the calls, B was rejected. The failing allocation can be the long-message copy (5,032 or 5,064 bytes for a 5,000-byte message) at every level, and at BiT-256 and -512 also the short-path copy (130 bytes for a 64-byte message) or the challenge hash's fixed 1,026- or 1,986-byte copy. BiT-128 hashes short messages with `sm3hash`, which does not allocate.

The long-message copy is sized by the message, so a long attacker-chosen message can make it fail under a memory limit. The candidate's defect is discarding the helpers' status and returning success. Demonstrated acceptance of a signature for a different message is High.

### Reproducing

```sh
sh sign-02/reproduce_stale_digest.sh
```

The witness checks the `void` helpers in all six trees, then builds each reference level with `malloc` wrapped so that exactly one allocation of the targeted size fails, and requires the signature on A to verify for B only in that case.

## sign-02-6: A failed mask-seed allocation makes signing reuse a stale seed and leaks the signing key

Severity: High
Status: Confirmed
Layer: Implementation
Affected: BiT-128, -256 and -512; reference and AVX2 implementations (identical by source; the witness runs the reference)
Discovery: Moderate
Exploitation: If one fixed-size allocation fails during signing, the call returns a valid signature whose masks come from a stale seed; s0 was recovered from public data, from one such signature at BiT-128 and -256 and from two at every level; no remote way to force the failure is shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19

Signing derives the mask seed `seed_y` from the secret seed, fresh randomness and the message digest (Fig. 5, physical p. 19, Sign line 7). In BiT-128 this is the `void` helper `bit_xof256_3` (`sign.c:99–100`), which casts the `pseudoXOF` status to `void` (`symmetric.c:127`); the other levels are the same. When `pseudoXOF`'s copy of its input fails (68, 132 or 196 bytes at the three levels), `temp_seed_y` keeps whatever its stack slot holds. A completed signing call ends with `secure_zero(temp_seed_y)` (`sign.c:200`), so the next faulty call at the same depth expands its masks from the all-zero seed.

With the reference code at all three levels, sixteen rounds of one ordinary signature followed by one faulty signature gave faulty signatures that verify. From the public key and the faulty signatures alone, s0 was recovered: from a single signature whose mask is the expansion of the all-zero seed (10 of 16 at BiT-128, 13 of 16 at BiT-256), and from pairs of faulty signatures with the same commitment at all three levels. Ordinary signatures gave neither.

The failing allocation has a fixed size and is not chosen by the attacker; memory pressure or a resource limit is needed. The candidate's defect is discarding the helper's status and returning a signature. Demonstrated key recovery is High.

### Reproducing

```sh
sh sign-02/reproduce_stale_mask.sh
```

The witness checks the `void` seed derivation in all six trees, wraps `malloc` to fail the derivation's copy once per faulty call, and requires the recovered s0 to equal the key's.
