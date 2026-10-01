<!-- synchronized report: sign-01/report.md -->
Candidate: Aigis-Sig+
Family: Lattice (Module-LWE/SIS, Fiat-Shamir)
Archive: [Aigis-Sig+.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Aigis-Sig%2B.zip) (SHA-256: `88242576a3ae8f9d090b0c9045020f04ee9b5ae828e01b839f25267959e9c7ea`)

## sign-01-1: Trivial signature malleability violates SUF-CMA

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/)

The packed hint has a variable meaningful length inside a fixed-size signature buffer. Verification decodes the meaningful portion but does not require a unique, canonical encoding of the remaining bytes.

Changing a sampled unused packed-hint bit in a valid signature produces a different byte string that still verifies for the same public key and message. No secret key or signing operation is needed to construct the second signature.

This does not by itself forge a signature for a new message, so it is not an EUF-CMA break. It does directly violate the specification's strong-unforgeability claim, because an attacker transforms one valid signature into a distinct valid signature on the same message.

### Proposed fixes

The [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/) proposes fixed-length signature encoding, zero padding for unused hint bits and bytes, and verification checks for invalid markers, excessive counts, duplicate or out-of-order positions, and nonzero padding. This section records the proposal without evaluating it.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-01
tools/ngcc_attack sig-malleable sign-01/lib/libAigis-sig1.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-01-2: Malformed hint counts cause an attacker-controlled stack write

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Unauthenticated denial of service; stronger memory-corruption impact is platform-dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/)

`unpack_h` reads the first attacker-controlled hint byte into `max` and uses it without checking the fixed capacity of the stack array `t`. It then sums attacker-controlled decoded counts into `k`, calls `unpack6bits(pos, sm, k)` without checking the `OMEGA`-element stack array `pos`, and uses the decoded positions as coefficient indices.

The exhaustive signature-bit reproducer reaches this field and triggers `*** stack smashing detected ***` during verification; for Aigis-sig1, signature bit 15617 is one confirmed crashing input. Because verification processes unauthenticated signatures, this is a remotely reachable stack-buffer overflow in the submitted API, distinct from the noncanonical-signature malleability in `sign-01-1`.

### Proposed fixes

The [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/) proposes checks for invalid hint markers, excessive hint counts, duplicate or out-of-order positions, nonzero padding, and signature lengths. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C api harness && make -C tools && make -C sign-01
tools/ngcc_attack sig-malleable sign-01/lib/libAigis-sig1.so
```

The command reports both the accepted noncanonical flips for `sign-01-1` and the number of flips that crash the verifier. The source defect is shared by the three submitted parameter sets.

## sign-01-3: Signature API ignores declared key-buffer lengths

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Aigis-Sig+ reference wrappers, all three parameter sets; runtime witness on set I
Discovery: Trivial
Exploitation: Out-of-bounds read or crash on a caller-supplied short key; no disclosure shown
Credit: Askus Li, with Askus Operator (Luna High) assistance
Date: 2026-09-23
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2ZTM3BMRATA6QTPA2OZSSSEBVBCTPHM6/), [GitHub PR #14](https://github.com/ngcc-dev/ngcc-harness/pull/14)
Follow-up source: [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/)

The submitted `sig_sign` and `sig_verify` wrappers discard `sk_len_bytes` and `pk_len_bytes` before `unpack_sk` and `unpack_pk` read the fixed-size keys. A one-byte key declared with length zero triggers an AddressSanitizer out-of-bounds read in each path. Applications that always pass the advertised key sizes do not encounter this defect; no remote disclosure or stronger exploit is demonstrated.

### Proposed fixes

The [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/) proposes checks for key, signature, and message lengths and the signature-length output pointer, plus resetting the output length to zero on signing failure. This section records the proposal without evaluating it.

### Reproducing

```sh
bash sign-01/reproduce_memory_safety.sh
```

The source-built set-I tests require Linux/GCC AddressSanitizer and print separate `CONFIRMED` lines for the short secret and public keys.

## sign-01-4: Honest signing writes one polynomial past the mask vector

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Aigis-Sig+ reference signers, all three parameter sets; runtime witness on set I
Discovery: Trivial
Exploitation: 2,048-byte stack-buffer write on the signer path; controlled corruption or key disclosure not shown
Credit: Askus Li, with Askus Operator (Luna High) assistance
Date: 2026-09-23
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2ZTM3BMRATA6QTPA2OZSSSEBVBCTPHM6/), [GitHub PR #14](https://github.com/ngcc-dev/ngcc-harness/pull/14)
Follow-up source: [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/)

`polyvecl_uniform_gamma1` fills `PARAM_L` polynomials and then calls `polyz_unpack(v->vec + i, outbuf)` once more after the loop, when `i == PARAM_L`. That writes an entire polynomial past the `polyvecl` object during honest signing. The extra call is present in all three reference sets. AddressSanitizer confirms the out-of-bounds stack write at `polyvec.c:214`; ordinary signing may appear to work because the adjacent stack layout varies. This is separate from `sign-01-2`'s attacker-input overflow in verification.

### Proposed fixes

The [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/) proposes removing the extra unpacking call after sampling `y`. This section records the proposal without evaluating it.

### Reproducing

```sh
bash sign-01/reproduce_memory_safety.sh
```

The set-I witness invokes the same mask sampler as the signer and requires an AddressSanitizer stack-buffer-overflow diagnostic at `polyvecl_uniform_gamma1`.

## sign-01-5: The challenge sampler collapses independent signs to one effective bit

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Aigis-Sig+-I and -II reference, AVX2, NEON, and AArch64 implementations
Discovery: Trivial
Exploitation: Most likely challenge costs about 2^213.46 work in set II; Grover cost about 2^68.59 in set I
Credit: Yijian Liu, with Doubao assistance
Date: 2026-09-27
Original source: [Liu's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PKKXNPUY433TLJHGCS365LENBN75SHAZ/)
Follow-up source: [Aigis-Sig+ team's confirmation and fix summary](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/)

Algorithm 24 assigns an independent sign to every nonzero challenge coefficient. In the `PARAM_C <= 64` implementation branch, however, the sampler sets one coefficient from `signs & 1` and then executes `signs = 0` instead of shifting to the next bit. This affects both set I (24 nonzero coefficients) and set II (44). For each support, one sign-bit value gives the all-positive challenge; the other leaves one negative coefficient whose position can vary as the sampler swaps coefficients. Thus set II has about `45*binomial(512,44) = 2^217.95` distinct outputs, but the most likely output has probability `1/(2*binomial(512,44))`. Its min-entropy, and the corresponding generic challenge-search work, is only `213.4609` bits. The specification instead defines

`binomial(512,44) * 2^44 = 2^256.4609` possible uniformly signed challenges.

The most likely set-II challenge therefore costs about `2^213.46` work, below its 256-bit claim. Set I similarly has `137.17` bits of min-entropy: this remains above its 128-bit classical claim, but Grover search costs about `2^68.59`, below its claimed 80-bit quantum level. Set III uses a separate branch and is unaffected. The team confirms the error.

### Proposed fixes

The [Aigis-Sig+ team's update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2BWLA2SMHII22YXJM6EWHVGE26WKG2PG/) proposes changing the random-sign handling for sets I and II in its reference, AVX2, and ARM implementations. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 sign-01/reproduce_challenge_entropy.py
```

The script checks the defective assignment in eight archived implementation copies across sets I and II. It computes the number of distinct outputs and the maximum output probability separately, since the outputs are not equally likely.

## sign-01-6: The abort bound violates the security proof's own precondition

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Aigis-Sig+ PARAMS I and PARAMS III security analysis
Discovery: Moderate
Exploitation: The printed quantitative proof bound is inapplicable; no forgery or key recovery demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Sun Shuzhou's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XT47M5GJTH4JRXLV3H55P3BZ4C2RNGVU/)

Section 7.3 sets the signing-abort upper bound to

`pbar = (1-exp(-n*l*beta1/gamma1)) + (1-exp(-n*k*(beta2+eta1)/gamma2))`.

At the Table 1 parameters this is 1.07668, 0.98003, and 1.16094 for sets I–III. The exact acceptance-probability formula in §3.4 gives repetition counts 6.408, 5.158, and 5.706, reproducing Table 2's rounded 6.41, 5.16, and 5.71 values. Theorems 1 and 2 and their supporting reductions explicitly require `0 < pbar < 1`, so the specification's chosen bound violates its own precondition for sets I and III. The sum double-counts overlap between the two abort events.

This does not disprove the theorems or give an attack. Section 3.4's own heuristic combined-abort estimate, `1-exp(-(a+b))`, is 0.844, 0.806, and 0.825, so an immediate bound below one is available. Correcting the loose union bound is local and leaves §7.3's final bound unchanged; the consequence is therefore Low / Proof gap.

### Reproducing

```sh
python3 sign-01/reproduce_abort_bound.py
```

The script evaluates the printed formula from the Table 1 parameters and checks the Table 2 repetition-rate control.
