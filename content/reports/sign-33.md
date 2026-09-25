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

Severity: Medium
Status: Proof gap
Layer: Design
Affected: VDOO-256 and VDOO-512 specification and proof
Discovery: Trivial
Exploitation: Proof gap; not by itself a concrete forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The VDOO specification fixes the salt at 16 bytes for both VDOO-256 and VDOO-512. Its own EUF-CMA bound contains the term `(q_s+q_h)q_s 2^-128`: it is already `2^-127` for one signing and one hash query and becomes order one around `2^64` signing queries.

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

### Reproducing

Inspect `vdoo_sign.c` lines 7–35, 82–105, and 127–159 in any reference parameter set. The `coeff` and `c` branch operands are obtained directly from `gfv_get_ele(sk->F, …)`. See `constant_time.md` for the secret/public review. This is a source/dataflow witness, not a measured remote timing exploit.

## sign-33-6: Restricted oil terms may enable a public-key-only VDOO forgery

Severity: Critical
Status: Probable
Layer: Implementation
Affected: VDOO-128, -256, and -512 reference implementations share the restricted coefficient mask; the reported forgery concerns VDOO-128
Discovery: Non-trivial
Exploitation: The original analysis reports an accepted fresh-message forgery using only the public key in about 12 minutes
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/mYN9Br_C8dg/m/BDmmwIE6BAAJ)

The VDOO specification gives each oil-layer equation products with every oil variable of that layer. The submitted coefficient filter permits a vinegar–oil product only when the oil variable has the same index as the output equation (`vdoo_keypair.c:194–225`), identically in all three reference sets. This creates a hidden one-variable-per-equation triangular system. The posted analysis describes a public-key-only structural search and reports a VDOO-128 forgery, but the search has no released code. The fixed replay regenerates both public and secret keys from the public trivial seed `seed[i]=i`, matches the posted public-key hash, and verifies the posted 85-byte signature; message and signature flips reject. Since that seed also permits ordinary honest signing, replaying the signature gives no evidence of how it was generated and does not independently establish a public-key-only forgery. This remains Probable on the original analysis. The optimized source is absent from the harness and was not checked here; the specified dense oil layers are unaffected.

### Reproducing

```sh
make -C sign-33 replay-forgery
sign-33/bin/replay_public_forgery
```

The replay checks the published public-key, message, and signature hashes before verifying the signature and two negative controls; it does not reproduce the public-key-only attack. Compare the specification's oil-layer sums with `is_allowed_oil1` and `is_allowed_oil2` in `vdoo_keypair.c` for the structural defect. The [original analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/mYN9Br_C8dg/m/BDmmwIE6BAAJ) describes the unreproduced public-key search.
