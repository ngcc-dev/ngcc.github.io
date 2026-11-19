<!-- synchronized report: sign-07/report.md -->
Candidate: CS
Family: Lattice (Module-LWE, Fiat-Shamir)
Archive: [CS.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CS.zip) (SHA-256: `c790d31cd4a288990f3d692381ed721a06641938a02dfc2e0435b7d323475cef`)

## sign-07-1: Trivial signature malleability violates SUF-CMA

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The signature contains a fixed-size rANS encoding area and an encoded byte count. `sigDecode` consumes only the indicated meaningful bytes and does not require the unused tail to be zero or otherwise canonical.

Changing the last unused signature byte produces a distinct signature that continues to verify for the same public key and message. This transformation needs neither the secret key nor a signing query beyond the original valid signature.

The result is not a new-message forgery and therefore does not alone violate EUF-CMA. It directly violates the submitted strong-unforgeability claim, which forbids producing a second accepted signature for an already signed message.

Verification must enforce a unique encoding, including the complete fixed-size tail.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-07
tools/ngcc_attack sig-malleable sign-07/lib/libCS-128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-07-2: Verifier challenge-sign blindness enables universal forgery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: CS-128, CS-256, and CS-512
Discovery: Non-trivial
Exploitation: Approximately 2^108.08, 2^212.46, and 2^394.18 hash trials, respectively
Credit: Kris Kwiatkowski <contact@amongbytes.com>
Date: 2026-09-21
Original source: [ngcc-harness PR #1](https://github.com/ngcc-dev/ngcc-harness/pull/1)

CS samples a weight-`tau` challenge over `{0,+1,-1}` and credits all `tau` sign bits in its challenge-entropy calculation. In both specification Algorithm 12 and `CS_Verify`, however, the challenge reaches verification only through parity: the `-q*c` term is identical for `+1` and `-1` modulo `2q`, and the other hash input retains only `LSB(z0-c)`. Verification therefore sees the challenge support but not its signs.

The verifier also imposes no independent weight or norm bound on the hint. For any chosen support, an attacker can set `z0=z1=0` and choose an encodable hint so that every norm and reconstruction check passes. Grinding the free hint until the hash selects that support costs `binomial(n,tau)`, rather than the `binomial(n,tau)*2^tau` challenge space used in Table 3. Independently recomputed costs are 108.08, 212.46, and 394.18 bits, below every claimed classical level; generic quantum search halves those exponents.

The complete submitted-size grinds were not executed. The reproducer proves the free-transcript construction at every submitted parameter set and runs the same attack to completion on a scaled CS-128 instance with `tau` reduced from 23 to 3. Compensating `B0`, `B1`, `B2`, and `M0` adjustments preserve the `z0` and `z1` bounds and tighten the `z2'` bound from 2812 to 2521. The submitted verifier compiled with those scaled parameters accepted the forged signature without a signing query or secret key. Binding the challenge signs into a verifier-visible equation and bounding the hint are both necessary repairs.

### Reproducing

```sh
make -C sign-07 libs exploit
sign-07/forgery_CS-128-scaled-tau3 \
  sign-07/lib/libCS-128-scaled-tau3.so --threads 4 --verbose
sign-07/forgery_CS-128 sign-07/lib/libCS-128.so \
  --control --threads 4 --trials 200000 --verbose
sign-07/forgery_CS-256 sign-07/lib/libCS-256.so \
  --control --threads 4 --trials 200000 --verbose
sign-07/forgery_CS-512 sign-07/lib/libCS-512.so \
  --control --threads 4 --trials 200000 --verbose
```

## sign-07-3: Compressed signatures enable practical equivalent-key recovery and forgery

Severity: Critical
Status: Confirmed
Layer: Design
Affected: CS-128 full compressed scheme; higher sets not evaluated
Discovery: Non-trivial
Exploitation: 2.3 million ordinary signatures for the demonstrated fixed key; 65.7 aggregate CPU minutes reported
Credit: Xianhui Lu and Yijian Liu, with AI assistance; practical completion by Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-24
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PNQJ4PBNVDPNY624PDPCOO7ZL2GXIP6H/)
Follow-up source: [Feussner's PKC Forum post and reproducer](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/YHC7FIZTNPJBTYDCH2H5JAYBR7Z4FEYH/)

In the full compressed scheme, §3.4 (Correctness) derives the verifier-visible relation `z2' = z2 - c_r·b_0 + (-LowBits_h(w,α)+LSB(w))/2 (mod ±q)`, where `b_0` is the secret low part of the public-key relation and `c_r` aggregates hidden bimodal signing signs. Liu reports estimating `E[c_r | z0,c]` from public signature fields, then using its correlation with `z2'` to recover all coefficients of `b_0`; a second cross moment reportedly recovers `s1`, from which the remaining short key follows. The cited experiment used `2^27` CS-128 signatures and reported exact 768-coefficient recovery after normalization.

Feussner's follow-up turns this into an end-to-end attack on one deterministic, ordinary CS-128 key. One million calibration signatures produce a rough public low-term estimate. For 1.3 million further signatures, posterior scoring tests all 64 hidden block-sign choices and regression produces a nearly correct ternary `s1`; a fixed public ladder completes an equivalent signing key. The submitted verifier accepts its signature on a fresh message. The immediately preceding 1.2-million refinement checkpoint fails.

The frozen sufficient statistics replay against source that is byte-identical to the archive after line-ending normalization. Replacing every secret-dependent diagnostic truth array with unrelated values leaves the first public success, completed key, and forgery unchanged, establishing that the recovery consumes only the public key and ordinary signature fields. We independently rebuilt and replayed that evidence. The experiment covers one preselected key and does not estimate success probability across keys or extend the result to CS-256/512. A practical fresh-message forgery nevertheless violates CS-128's EUF-CMA claim and is Critical.

### Reproducing

Download the reproducer pinned at commit `c66f8b06b9033d0be076db7a8bdaebb2158ad493` (archive SHA-256 `0fe62b6b330b3ece432013ca14a1ee35f3e2315ff36d6ac776e1a9134ad67b39`) and run its frozen evidence replay:

```sh
T=$(mktemp -d)
curl -fL -o "$T/cs.tar.gz" \
  'https://github.com/martinfeussner/NGCC-Signature-Audit/archive/c66f8b06b9033d0be076db7a8bdaebb2158ad493.tar.gz'
printf '%s  %s\n' \
  '0fe62b6b330b3ece432013ca14a1ee35f3e2315ff36d6ac776e1a9134ad67b39' \
  "$T/cs.tar.gz" | sha256sum -c -
tar -xzf "$T/cs.tar.gz" -C "$T"
cd "$T"/NGCC-Signature-Audit-*/CS/reproducer
CFLAGS='-O3 -flto -fcommon -std=gnu11 -Wno-error=implicit-int' \
  ./verify_evidence.sh
```

The extra warning flag lets current GCC accept two pre-existing implicit-`int` declarations in the archived source. The replay verifies all evidence and submitted-source hashes, recomputes the posterior/refinement ladder, requires rejection through 1.2 million refinement signatures and an accepted fresh-message forgery at 1.3 million, then repeats with poisoned diagnostic truth. `run_full.sh` performs the approximately 2.3-million-signature collection instead.

## sign-07-4: A missing nonce collapses every secret and error polynomial to one value

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CS-128, CS-256, and CS-512, reference and optimized implementations
Discovery: Moderate
Exploitation: Public-key recovery estimates of about 2^42.6, 2^114.7, and 2^95.5 operations
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-04
Original source: [Sun Shuzhou's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2OEX5VKCOX3NZV2DFKG3DF7B3OA6Z3FC/)

The specification says that `ExpandS` derives a child seed for each component of `s1` and `s2` (physical p. 9). `RejBoundedPoly` writes the intended two-byte nonce at `rho[HBYTES]`, but seeds the ICCS DRBG expander with only `SEEDBYTES+2` bytes (`sampling.c:240–253`). Since `HBYTES=2*SEEDBYTES`, the nonce lies outside the consumed prefix. All `l+k` calls therefore return the same ternary polynomial `p`; fresh keys confirm that every packed `s1` and `s2` block is identical. The bug is byte-identical in all six submitted source trees.

The public relation consequently collapses from module-LWE to one secret polynomial. If `A_ij` are the public matrix entries and `2^beta*t1_i+t0_i=sum_j A_ij*s_j+e_i`, then

```text
2^beta*t1_i = (1 + sum_j A_ij)*p - t0_i  (mod q),
```

where every coefficient of the public-key rounding residual `t0_i` is bounded by `2^(beta-1)`. Here `beta` denotes the implementation's rounding exponent, not the unrelated parameter β in the specification. Scalarizing these public negacyclic equations gives ordinary bounded-error LWE with dimension `n` and `k*n` samples, instead of the submitted MLWE instance.

At pinned `lattice-estimator` commit `53da598`, the ADPS16/Core-SVP model gives best costs of about 42.6, 114.7, and 95.5 bits for CS-128/256/512. The post's independent models give 43.7/113.3/94.0 bits under its Core-SVP settings and 68.8/135.9/118.0 with MATZOV costing. All are far below the respective 128-, 256-, and 512-bit targets claimed on physical pp. 33 and 35. The estimates are heuristic lattice costs rather than completed full-size runs; the post reports exact recovery on otherwise faithful `n=32` and `n=64` scaled instances. The exact public reduction plus the large modeled shortfalls violate the claimed levels and are Critical.

### Reproducing

```sh
make -C sign-07 libs
python3 sign-07/reproduce_expand_s_collapse.py
LATTICE_ESTIMATOR_PATH=/path/to/lattice-estimator \
  /path/to/sage/python sign-07/reproduce_expand_s_estimate.py
```

The first witness generates fresh submitted keys, requires every packed secret/error polynomial to be identical, checks a changed-seed control, and verifies the faulty seed length in all source copies. The Sage witness checks the estimator commit and reproduces the three independent Core-SVP estimates; it does not perform full-size key recovery.

## sign-07-5: 32-bit message lengths give long-message forgeries

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CS-128, CS-256 and CS-512 reference implementation (the optimized `cs.c` and `symmetric.h` are identical)
Discovery: Trivial
Exploitation: A signature on a 32-byte message verified on fresh messages of 2^29 + 32 and 2^32 + 32 bytes at all three levels; one signing query
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

CS computes µ := H(H(pk), M) in signing and verification (§3.3, Algorithm 11 line 3, p. 20, and Algorithm 12 line 4, p. 21) and claims sUF-CMA security (§4.2, Theorem 4.1, p. 28). `CS_Sign` and `CS_Verify` take the message length as `int len` (`cs.c:65–68,151–154`), although the wrapper passes the 64-bit `m_len_bytes` (`SIG_AlgorithmInstance.c:46–61`). The hash is the macro `H(OUT, OUTLEN, IN, INLEN) pseudoXOF((OUTLEN) * 8, IN, (INLEN) * 8, OUT)` (`symmetric.h:10`), which multiplies the length by 8 in 32-bit `int`, and µ is computed as `H(mu, HBYTES, buf, HBYTES + len)` (`cs.c:86–89,173–177`). At `|M| = 2^29 + j` the bit length wraps to `8 · (HBYTES + j)`. At `|M| = 2^32 + j` the conversion to `int len` already truncates the message to `j` bytes. In both cases µ depends only on `H(pk) ∥ M[:j]`.

A signature on any short message `m` therefore also verifies on every message of `2^29 + |m|` or `2^32 + |m|` bytes that begins with `m`. Both lengths are within the call's required message range of up to `2^63` bits ([Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf) §2(2)). This is a one-query fresh-message EUF-CMA forgery and also breaks the sUF-CMA claim.

Natively, `lib/libCS-128/256/512.so` accepted the 32-byte message's signature on `m ∥ 0^(2^29)`, on `m ∥ 0xa5^(2^29)` and on `m ∥ 0^(2^32)`. With the first byte changed, those long messages were rejected, as were `m ∥ 'x'` and the `2^32 + j + 1`-byte message (which hashes `m ∥ 0x00`). For `2^28 ≤ HBYTES + |M| < 2^29` the bit length is negative and `pseudoXOF` fails. The verifier then uses µ = H(pk), but the signer leaves µ uninitialized, so honest signatures in that range fail to verify; no forgery is claimed there. The length must be carried as `size_t` and the bit length computed in 64 bits.

### Reproducing

```sh
python3 sign-07/reproduce_message_length_overflow.py
```

The script signs a 32-byte message at each level and verifies the long forgeries, held in anonymous `mmap` buffers, and their controls, each in a fresh process. It takes under 10 seconds and needs about 1 GiB of memory.

## sign-07-6: Signing masks depend on only half of the mask seed

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: CS-128, CS-256 and CS-512; reference and optimized implementations
Discovery: Moderate
Exploitation: Two signing calls whose mask seeds agree in their first λ bits draw identical masks, which is expected after about 2^(λ/2) signatures (2^64 for CS-128); the consequence of a repeated mask is not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
Algorithm 11 derives a mask seed `ρ′` of 2λ bits (line 5, p. 20) and expands every mask component from it. `CS_Sign` computes the full `rhoprime[HBYTES]` and passes it to `ExpandMask` (`cs.c:76,95,99`), but `ExpandMask` copies only `SEEDBYTES` bytes of it before hashing (`sampling.c:668–676`). `HBYTES` is λ/4 and `SEEDBYTES` is λ/8 (`params.h:88–89`), so the masks are a function of the first λ bits of `ρ′` and the counter. The function's own comment describes a seed of length `HBYTES`.

With the archived code at all three levels, changing any byte in the upper half of `ρ′` leaves every mask unchanged, while one flipped bit in the lower half changes them. The upper half reaches only the coin stream of the sampler.

The mask seed therefore has λ bits of collision space where the specification provides 2λ. Among about 2^(λ/2) signatures two share all masks; for CS-128 that is 2^64 signatures. In Fiat–Shamir signatures a repeated mask with different challenges relates the two responses through the secret, and other candidates here have lost keys that way. For CS the responses also pass through a coin-driven sampling step, and we did not analyse what a repeated mask yields or run a recovery. The entropy shortfall is confirmed and its consequence is unresolved, hence Medium.

### Reproducing

```sh
d=sign-07/Implementations/Reference_Implementation/CS-128
sed -n '668,676p' "$d/sampling.c"; grep -n 'ExpandMask(y' "$d/cs.c"
grep -n 'define HBYTES\|define SEEDBYTES' "$d/params.h"
```

This is a source witness. The unchanged masks were observed by calling the archived `ExpandMask` with seeds differing in the upper half, and are not part of the witness.

## sign-07-7: The zero-knowledge simulator uses part of the secret key

Severity: Medium
Status: Proof gap
Layer: Design
Affected: All three CS parameter sets; Lemma 4.3 and the reduction to Theorem 4.1
Discovery: Moderate
Exploitation: The paHVZK step of the security proof is not established as written; no forgery or key recovery follows
Credit: Xifeng Jin (CertiK), with AI assistance
Date: 2026-11-16
Original source: [Jin's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SHC42EUTFQL7IQWFX4JAJKQAZLU5S34Q/)

Definition 4.4 (physical p. 26) requires a simulator `Sim(x)` that is given only the public instance. Key generation splits `b = A′s1 + s2` into `b1 = HighBits(b, β)` and `b0 = LowBits(b, β)`, puts `b1` in the public key and keeps `b0` in the secret key (Algorithm 10, physical p. 19). The simulator in the proof of Lemma 4.3 starts "with only the public key, `b0`, and the ability to control the hash function". It computes `w = Az − qcj − 2c_r b0 mod 2q` in step 4 and uses `b0` again for the hint in step 6 (physical pp. 29–30).

No way of obtaining `b0` from the public key is given, so the displayed simulator does not satisfy Definition 4.4. Lemma 4.3 feeds the reduction behind Theorem 4.1, which therefore does not establish paHVZK as stated. A simulator using only the public key may exist; the proof does not supply one.

### Reproducing

```sh
pdftotext -f 19 -l 19 -layout sign-07/sign-07-spec.pdf - | grep 'pk = (ρ0\|sk = ('
pdftotext -f 29 -l 30 -layout sign-07/sign-07-spec.pdf - | grep -B1 -A1 'b0'
```

This is a specification witness: `pk = (ρ0, b1)`, `sk = (…, b0)`, and the simulator's use of `b0`.

## sign-07-8: The specified rANS coder does not round-trip its input

Severity: Low
Status: Confirmed
Layer: Design
Affected: The written rANS algorithms (§2.6) and their use in Algorithm 12, all three parameter sets; the submitted C code uses a different coder and is not shown to be affected
Discovery: Moderate
Exploitation: A verifier written from the specification decodes some encodings to the wrong sequence; no forgery demonstrated
Credit: Xifeng Jin (CertiK), with AI assistance
Date: 2026-11-16
Original source: [Jin's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SHC42EUTFQL7IQWFX4JAJKQAZLU5S34Q/)

Section 2.6 states that rANS decoding recovers the original symbol sequence. Algorithm 2 starts the encoder at `x0 = 0`, and Algorithm 3 decodes while its state is positive and then sets `m = i − 1` (physical p. 12). The forum post's example uses `t = 2`, four symbols with `g(s) = 1` and `CDF(s) = s`. Encoding `[1]` gives `x1 = 1`. Decoding takes one step to state 0 and then returns the empty sequence, since `m = 0`. Encoding `[0, 1]` also gives 1, so changing `m = i − 1` to `m = i` would still leave the encoding ambiguous: a leading zero-valued symbol leaves the state at 0. We checked the arithmetic.

Algorithm 12 decodes the response components `z0` and `z1` with `rANS.Decode`, and the correctness argument of Theorem 3.1 assumes they come back unchanged. The written algorithms do not justify that. The submitted C code starts from a nonzero normalized state and decodes a fixed number of coefficients, so this concerns the specification only.

### Reproducing

```sh
pdftotext -f 12 -l 12 -layout sign-07/sign-07-spec.pdf - | grep -A20 'Algorithm 2 rANS encoding'
```

This is a specification witness for Algorithms 2 and 3; the counterexample follows by hand from lines 2, 4 and 8.

## sign-07-9: Rejected verifications leak the message buffer, and verification reads past a short signature

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: CS-128, -256 and -512; all six trees by source for the leak, the reference API wrapper for the signature length (the optimized tree has no wrapper)
Discovery: Trivial
Exploitation: Unbounded memory growth in a long-running verifier fed invalid signatures, and an out-of-bounds read of a caller-supplied signature shorter than its encoded fields; no disclosure shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GJYAU25KUS55A23YWEK6BP6HGH4XI76I/)

`CS_Verify` allocates `buf = malloc(len + HBYTES)` (`cs.c:157`) and frees it only on the accepting path; its four `return false` exits (decoding failure, the two norm bounds and the challenge mismatch) leak it. At all three levels, 100 rejected verifications of a 28-byte message, by challenge mismatch or by a decoding failure, left 100 blocks of 60, 92 or 156 bytes; 100 accepted ones left none.

The reference `sig_verify` passes the signature to `CS_Verify` without its length. Honest signatures end in unused padding (11, 17 and 23 bytes in the run), so a buffer one byte short of the full length is not over-read, but a buffer one byte shorter than the bytes the rANS fields occupy, declared at that length, is read past its end in `sigDecode` under AddressSanitizer. Callers that pass complete signatures are unaffected by this part.

### Reproducing

```sh
sh sign-07/reproduce_verify_memory.sh
```
