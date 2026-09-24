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

The packed hint has a variable meaningful length inside a fixed-size signature buffer. Verification decodes the meaningful portion but does not require a unique, canonical encoding of the remaining bytes.

Changing a sampled unused packed-hint bit in a valid signature produces a different byte string that still verifies for the same public key and message. No secret key or signing operation is needed to construct the second signature.

This does not by itself forge a signature for a new message, so it is not an EUF-CMA break. It does directly violate the specification's strong-unforgeability claim, because an attacker transforms one valid signature into a distinct valid signature on the same message.

The decoder must reject noncanonical hint encodings and require every unused byte or bit to have its unique prescribed value.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-01
tools/ngcc_attack sig-malleable sign-01/lib/libAigis-sig1.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-01-2: Malformed hint counts cause an attacker-controlled stack write

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Unauthenticated denial of service; stronger memory-corruption impact is platform-dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

`unpack_h` reads the first attacker-controlled hint byte into `max` and uses it without checking the fixed capacity of the stack array `t`. It then sums attacker-controlled decoded counts into `k`, calls `unpack6bits(pos, sm, k)` without checking the `OMEGA`-element stack array `pos`, and uses the decoded positions as coefficient indices.

The exhaustive signature-bit reproducer reaches this field and triggers `*** stack smashing detected ***` during verification; for Aigis-sig1, signature bit 15617 is one confirmed crashing input. Because verification processes unauthenticated signatures, this is a remotely reachable stack-buffer overflow in the submitted API, distinct from the noncanonical-signature malleability in `sign-01-1`.

The decoder must reject `max` beyond `PARAM_K * PARAM_N / SEC`, reject cumulative counts beyond `OMEGA`, validate every encoded position before indexing a polynomial, and validate the encoded input length before every read.

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
Credit: Askus Operator (Luna High), with human review by Askus Li
Date: 2026-09-23
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2ZTM3BMRATA6QTPA2OZSSSEBVBCTPHM6/), [GitHub PR #14](https://github.com/ngcc-dev/ngcc-harness/pull/14)

The submitted `sig_sign` and `sig_verify` wrappers discard `sk_len_bytes` and `pk_len_bytes` before `unpack_sk` and `unpack_pk` read the fixed-size keys. A one-byte key declared with length zero triggers an AddressSanitizer out-of-bounds read in each path. Applications that always pass the advertised key sizes do not encounter this defect; no remote disclosure or stronger exploit is demonstrated.

### Reproducing

```sh
bash sign-01/reproduce_memory_safety.sh
```

The source-built set-I tests require Linux/GCC AddressSanitizer and print separate `CONFIRMED` lines for the short secret and public keys.

## sign-01-4: Honest signing writes one polynomial past the mask vector

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Aigis-Sig+ reference signers, all three parameter sets; runtime witness on set I
Discovery: Trivial
Exploitation: 2,048-byte stack-buffer write on the signer path; controlled corruption or key disclosure not shown
Credit: Askus Operator (Luna High), with human review by Askus Li
Date: 2026-09-23
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2ZTM3BMRATA6QTPA2OZSSSEBVBCTPHM6/), [GitHub PR #14](https://github.com/ngcc-dev/ngcc-harness/pull/14)

`polyvecl_uniform_gamma1` fills `PARAM_L` polynomials and then calls `polyz_unpack(v->vec + i, outbuf)` once more after the loop, when `i == PARAM_L`. That writes an entire polynomial past the `polyvecl` object during honest signing. The extra call is present in all three reference sets. AddressSanitizer confirms the out-of-bounds stack write at `polyvec.c:214`; ordinary signing may appear to work because the adjacent stack layout varies. This is separate from `sign-01-2`'s attacker-input overflow in verification.

### Reproducing

```sh
bash sign-01/reproduce_memory_safety.sh
```

The set-I witness invokes the same mask sampler as the signer and requires an AddressSanitizer stack-buffer-overflow diagnostic at `polyvecl_uniform_gamma1`.
