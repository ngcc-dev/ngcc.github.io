<!-- synchronized report: sign-33/report.md -->
Candidate: VDOO
Family: Multivariate (UOV family)
Archive: [VDOO.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/VDOO.zip) (SHA-256: `4b7bb0f15388b395b9308ae480f25622105a734f0ab4a6bd16398438c4b9752a`)

## sign-33-1: Publicly reproducible signing keys

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The implementation declares the API-provided `drng_algorithm` but never reads it. Key generation instead uses a second file-local global DRNG object that is never initialized by the shared-library wrapper and therefore starts from zero-initialized process memory.

Independent fresh-process tests with different API seeds generated identical VDOO public and secret keys. The result was directly reproduced against the built VDOO-256 library and the same RNG wiring is used by all submitted levels.

An attacker recovers the victim's secret signing key by starting a fresh process and invoking key generation once. No multivariate cryptanalysis is required.

All key-generation randomness must be derived from the initialized API DRNG; the uninitialized private generator must be removed or explicitly and securely seeded.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-33
tools/ngcc_attack keygen-fresh sign-33/lib/libvdoo_128.so 0x01
tools/ngcc_attack keygen-fresh sign-33/lib/libvdoo_128.so 0x99   # same key digest
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-33-2: A 256-bit implementation prehash limits forgery security to 128 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: VDOO-256 and VDOO-512 reference wrappers; specification leaves the wrapper prehash undefined
Discovery: Trivial
Exploitation: Approximately 2^128 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The VDOO-256 and VDOO-512 wrappers first hash every arbitrary-length message to a 32-byte digest and pass only that digest to the specified signing transform. Two messages with the same inner digest therefore produce the same signing input. A generic birthday search costs about `2^128` hash evaluations; after obtaining a signature on one colliding message, the attacker transfers it unchanged to the other. This is below both the 256- and 512-bit classical claims.

The specification types its message hash as mapping directly to the MQ target space and does not clearly require this 32-byte truncation. This finding is therefore an implementation/specification conformance break, not a clean property of the normative VDOO design.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The `sign-33-2` check traces the 32-byte wrapper prehash in the VDOO-256 and VDOO-512 sources.

## sign-33-3: The VDOO-256 and -512 proof bound contains a 128-bit salt term

Severity: High
Status: Proof gap
Layer: Design
Affected: VDOO-256 and VDOO-512 specification and proof
Discovery: Trivial
Exploitation: Proof gap; not by itself a concrete forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The VDOO specification fixes the salt at 16 bytes for both VDOO-256 and VDOO-512. Its own EUF-CMA bound contains the term `(q_s+q_h)q_s 2^-128`: it is already `2^-127` for one signing and one hash query and becomes order one around `2^64` signing queries. The [NGCC Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/tT7TSQiz.pdf) §1(2) permits up to `2^80` chosen-message signatures, so the submitted reduction fails to cover the evaluation budget by an even wider margin.

This is a specification-level parameter and proof gap: the stated reduction cannot substantiate either the 256- or 512-bit EUF-CMA claim. It is not, by itself, a concrete forgery and is reported separately from `sign-33-2`.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The `sign-33-3` check verifies the normative salt length and the corresponding
term in the submitted EUF-CMA bound.

## sign-33-4: Signing reuses a publicly predictable randomness stream

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Repeated-vinegar UOV key-recovery vector
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Signing uses the same never-initialized file-local generator identified in `sign-33-1` for the salt, free vinegar variables, and random diagonal solutions. A fresh process therefore restarts a publicly predictable signing-randomness stream. The defect remains even if KeyGen is repaired without also changing signing.

In a UOV-family construction, reuse of vinegar values for different message targets exposes relations in the central equations and is a key-recovery vector. Predictable salts also defeat the proof's assumption that each signing query receives fresh randomness. This finding tracks the signing failure separately from the immediately reproducible signing-key failure in `sign-33-1`.

Signing must initialize a per-operation generator from the API DRNG and domain-separate the randomness used for its salt, vinegar variables, and diagonal solving.

### Reproducing

The three `vdoo_sign.c` implementations obtain salt, vinegar, and diagonal randomness through `get_randombytes` backed by the uninitialized private generator. The permanent witness changes both the API seed and message between fresh processes:

```sh
tools/reproduce.sh sign-33
```

It reports identical signing-key and encoded-salt digests. Source inspection shows that the continued same generator stream supplies the vinegar and diagonal randomness as well.

## sign-33-5: Signing branches directly on private central-map coefficients

Severity: Medium
Status: Probable
Layer: Side-channel
Affected: VDOO reference signer, all three parameter sets
Discovery: Trivial
Exploitation: Local timing/power side channel; no independent full-key extraction demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`vdoo_sign.c` reads coefficients from the private central map `sk->F` and branches on whether each is zero (lines 21–35 and 85–103). Secret-derived diagonal and Gaussian pivots also control retries. Consequently the instruction/power trace depends directly on private key values. This is separate from the already stronger predictable-key defect `sign-33-1`; it matters if that RNG defect is repaired without making signing constant-time. No side-channel key-recovery experiment is claimed.

Constant-time fix (moderate, hence Medium): process every central-map coefficient unconditionally instead of skipping zeros, and use constant-time Gaussian elimination that adds candidate pivot rows under masks, a well-known technique in constant-time UOV and MAYO implementations. It processes every row at every step, a moderate cost; a retry on a singular system is the usual accepted exception.

### Reproducing

Inspect `vdoo_sign.c` lines 7–35, 82–105, and 127–159 in any reference parameter set. The `coeff` and `c` branch operands are obtained directly from `gfv_get_ele(sk->F, …)`. See `constant_time.md` for the secret/public review. This is a source/dataflow witness, not a measured remote timing exploit.

## sign-33-6: Restricted oil terms enable a public-key-only VDOO forgery

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: VDOO-128, -256, and -512 reference and optimized implementations share the restricted coefficient mask; the demonstrated forgery concerns VDOO-128
Discovery: Non-trivial
Exploitation: Public-key-only VDOO-128 fresh-message forgery accepted in 157 seconds with no signing queries; changed-message and changed-signature controls reject
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/mYN9Br_C8dg/m/BDmmwIE6BAAJ)

The VDOO specification gives each oil-layer equation products with every oil variable of that layer (§4.3, p. 7) and bases its security estimates on that map (§7.3, p. 22). The submitted coefficient filter permits a vinegar–oil product only when the oil variable has the same index as the output equation (`vdoo_keypair.c:194–225` in the reference trees and lines 192–224 in the optimized trees), identically in all three parameter sets. This creates a hidden one-variable-per-equation triangular system. The released VDOO-128 attack recovers the two oil quotient spaces and the diagonal flag from the public quadratic map, solves the resulting triangular system, lifts the solution, and emits an 85-byte fresh-message signature accepted by the submitted verifier.

We reproduced the complete uncached attack against the posted public key, which the package regenerates from the public 48-byte API seed `00..2f`. That seed can also regenerate the corresponding honest secret key, but the audited `--pk` attack path receives only the serialized public-key bytes. The full run recovered all structural layers and forged a different message without a signing query or secret-key input. The saved-evidence verifier separately requires message and signature mutations to reject. This establishes a public-key-only EUF-CMA break and upgrades the finding from Probable to Confirmed. The specified dense oil layers are unaffected.

### Reproducing

```sh
sign-33/reproduce_public_structural_forgery.sh
VDOO_FULL=1 sign-33/reproduce_public_structural_forgery.sh
```

The default mode downloads and hash-checks Feussner's [package at commit `91f2ddf`](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/91f2ddf0590a24ad39afc2ce2ee4f2627ec54726/VDOO), replays the saved public-key-only forgery, and requires changed-message and changed-signature controls to reject. `VDOO_FULL=1` repeats the uncached public-map recovery through the public-key-only `--pk` path and forges a different message (about 12 minutes on the reporter's machine; 157 seconds on the validation host). Both modes require Python with NumPy.
