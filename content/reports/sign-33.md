<!-- synchronized report: sign-33/report.md -->
Candidate: VDOO
Family: Multivariate (UOV family)
Archive: [VDOO.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/VDOO.zip) (SHA-256: `4b7bb0f15388b395b9308ae480f25622105a734f0ab4a6bd16398438c4b9752a`)

## sign-33-1: Publicly reproducible signing keys

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized implementations, all three parameter sets
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
Affected: VDOO-256 and VDOO-512 reference and optimized wrappers; specification leaves the wrapper prehash undefined
Discovery: Trivial
Exploitation: Approximately 2^128 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The VDOO-256 and VDOO-512 wrappers first hash every arbitrary-length message to a 32-byte digest and pass only that digest to the specified signing transform. Two messages with the same inner digest therefore produce the same signing input. A generic birthday search costs about `2^128` hash evaluations; after obtaining a signature on one colliding message, the attacker transfers it unchanged to the other. This is below both the 256- and 512-bit classical claims.

The specification types its message hash as mapping directly to the MQ target space and does not clearly require this 32-byte truncation. This finding is therefore an implementation/specification conformance break, not a clean property of the normative VDOO design.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-33-2
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
python3 security/design_parameter_audit.py --report-id sign-33-3
```

The `sign-33-3` check verifies the normative salt length and the corresponding
term in the submitted EUF-CMA bound.

## sign-33-4: Signing reuses a publicly predictable randomness stream

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized implementations, all three parameter sets
Discovery: Trivial
Exploitation: Predictable and repeated signing randomness across fresh processes; key recovery or forgery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Signing uses the same never-initialized file-local generator identified in `sign-33-1` for the salt, free vinegar variables, and random diagonal solutions. A fresh process therefore restarts a publicly predictable signing-randomness stream. The defect remains even if KeyGen is repaired without also changing signing.

In a UOV-family construction, two signatures with reused vinegar values expose a difference in the secret oil-type subspace; a handful of such differences is the standard route to recovering that subspace and then the signing key. Starting one fresh process per signature supplies the reuse precondition here. VDOO's layered central map means the plain-UOV recovery does not carry over unchanged, and no VDOO-specific recovery, forgery, or complexity estimate is established. This is therefore a confirmed leak with a well-known candidate-relevant recovery path still needing a VDOO-specific step: High rather than Critical. Predictable salts also defeat the proof's assumption that each signing query receives fresh randomness.

Signing must initialize a per-operation generator from the API DRNG and domain-separate the randomness used for its salt, vinegar variables, and diagonal solving.

### Reproducing

The three `vdoo_sign.c` implementations obtain salt, vinegar, and diagonal randomness through `get_randombytes` backed by the uninitialized private generator. The permanent witness changes both the API seed and message between fresh processes:

```sh
tools/reproduce.sh sign-33
```

It reports identical signing-key and encoded-salt digests. Source inspection shows that the continued same generator stream supplies the vinegar and diagonal randomness as well.

## sign-33-5: Signing branches directly on private central-map coefficients

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: VDOO reference and optimized signers, all three parameter sets
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

## sign-33-7: Moving the message/signature boundary forges new messages

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: VDOO-128, -256 and -512 reference and optimized implementations (all six wrapper files are byte-identical)
Discovery: Trivial
Exploitation: From one honest signature, a shorter prefix message and a longer extended message that were never signed verified at all three levels; no key material or cryptanalysis is needed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

The specification defines verification on a message and a fixed-format signature σ = (s, salt) (§4.6, Algorithm 5, pp. 9–10). The detached NGCC wrapper `sig_verify` never checks `sn_len_bytes`. It copies `m || sn` into one buffer and passes the concatenation to `crypto_sign_open` (`SIG_AlgorithmInstance.c:61–83`). That function always treats the last `CRYPTO_BYTES` as the signature and everything before them as the message (`api.c:39–48`). The boundary that the caller supplied is therefore discarded: any split of the same byte string `m || sn` into a message and a "signature" verifies.

Given a valid signature `sn` on `m`, an attacker chooses any nonempty suffix `x` of `m`, writes `m = m' || x`, and presents the fresh message `m'` with the detached signature `x || sn`. In the other direction, the extended message `m || sn[:k]` verifies with the signature `sn[k:]`. In both cases the wrapper rebuilds exactly the honestly signed `m || sn`. From a signature on "Transfer 1000 CNY to account 42", the unsigned message "Transfer 100" verified at VDOO-128, -256 and -512. This is a one-query existential forgery on a message that was never signed, which breaks the EUF-CMA claim (§5.7, p. 19).

The defect is in the API glue, not in the VDOO equations. The verifier must reject any `sn_len_bytes != CRYPTO_BYTES` and verify the caller's message and signature separately rather than re-splitting their concatenation.

### Reproducing

```sh
python3 sign-33/reproduce_boundary_forgery.py
```

At each level the script signs one message, then verifies two prefix forgeries and one extension forgery, each as the first library call in a fresh process. Controls (the honest signature, a changed message, the prefix with the unmodified signature, and each forged signature with one bit flipped) must give the expected verdicts. It takes about 80 seconds, mostly VDOO-512 key generation.

## sign-33-8: Four unused response bits in VDOO-128 are unauthenticated

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: VDOO-128 reference and optimized implementations; VDOO-256 and -512 store one GF(256) element per byte and have no padding
Discovery: Trivial
Exploitation: All 16 values of the high nibble of signature byte 68 verify for the same message; no fresh-message forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

VDOO-128 packs its `N = 137` GF(16) response elements two per byte into `VDOO_N_BYTE = 69` bytes, followed by the 16-byte salt (`vdoo_config.h:5–9,51,80–82`). `vdoo_verify` reads only elements 0 through 136 (`vdoo_verif.c:35–36,82–100`). The high nibble of byte 68 would hold a 138th element and is never read or required to be zero. The signer zeroes it (`vdoo_sign.c:248`), but the verifier accepts any value. The specification's signature σ = (s, salt) has no such padding (§4.6, Algorithm 5, pp. 9–10).

A native scan flipped each of the 680 bits of an honest VDOO-128 signature. Exactly four flips verified, bits 4–7 of byte 68. All 15 nonzero high-nibble changes then verified in fresh processes, while changes to element 136 (the low nibble of byte 68), to element 135 and to the salt were rejected. Each honest signature therefore has 16 accepted encodings.

These are signature aliases on an already-signed message, not a forgery on a new message. VDOO claims EUF-CMA (§5.7, p. 19) and not strong unforgeability, so the defect matters to applications that identify signatures by their bytes (replay caches, transaction identifiers or deduplication). The verifier should reject a nonzero high nibble in byte 68.

### Reproducing

```sh
python3 sign-33/reproduce_padding_nibble.py
```

The script runs the 680-bit scan in a child process separate from the signer and requires exactly bits 68.4–68.7 to be accepted. It then re-verifies the 15 high-nibble aliases, the honest and changed-message controls and the low-nibble and salt controls, each in its own fresh process. It takes about 2 seconds.

## sign-33-9: A wedge-intersection attack on VDOO-512 is estimated at 2^379 gates

Severity: Critical
Status: Lead
Layer: Design
Affected: VDOO-512 specification and parameter set
Discovery: Non-trivial
Exploitation: Reported key-recovery estimate of about 2^379.18 gates under semi-regularity and generic-rank heuristics; not executed
Credit: Siyu Li, Hao Guo, Peigen Li, and Siyong Tao
Date: 2026-10-19
Reference: [Li, Guo, Li, and Tao, *Revisiting the Security of VDOO*, ePrint 2026/2528](https://eprint.iacr.org/2026/2528)

The authors [announced the `2^379` estimate on 2026-09-21](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/LA5Z--9hCTU), with details deferred to the paper. The paper observes that retaining only VDOO's last oil space gives a generalized UOV instance. For VDOO-512, the submitted parameters `(q, v, d, o1, o2) = (256, 260, 10, 10, 175)` yield `UOV(n = 455, o = 175, m = 195)`. Applying the published wedge-reconciliation estimate with `(k, D, l) = (123, 52, 1)` costs about `2^432.10` gates. The stronger wedge-intersection variant gives `UOV(n = 455, o = 70, m = 583)` and, with `(k, D, l) = (33, 37, 1)`, costs about `2^379.18` gates. Both figures are below the claimed 512-bit level; the latter is about 133 bits below it. The same calculation gives about `2^172.20` and `2^947.65` gates at the 128- and 256-bit sets, so this finding affects only VDOO-512.

After recovery of the final oil space, polar images are expected to span the corresponding hidden output space. The last layer can then be removed and the residual multilayer trapdoor recovered with polynomial overhead. The attack uses the specified VDOO structure and parameters; it does not depend on any implementation defect.

The numerical estimate assumes semi-regular public polynomials in the truncated ring used by the wedge analysis. The output-space step additionally assumes generic rank, although its full-span condition can be checked after recovering the oil space. Neither a full-size wedge computation nor VDOO-512 key recovery has been performed. The report therefore records a quantified below-target design attack as `Critical / Lead`, not as a confirmed key recovery.

### Reproducing

```sh
python3 sign-33/reproduce_wedge_estimate.py
```

The certificate recomputes the truncated-Hilbert-series coefficients and gate conversions for all four estimates quoted above. It confirms the paper's arithmetic, not its semi-regularity or generic-rank heuristics.
