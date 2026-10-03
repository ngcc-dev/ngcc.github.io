<!-- synchronized report: sign-32/report.md -->
Candidate: UVW
Family: Code-based (Wave-type, syndrome decoding over F3)
Archive: [UVW signature.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/UVW%20signature.zip) (SHA-256: `bbfa8dad5ee57083578b50b9937e773e6158f72646e825da3d3265cc00cb1294`)

## sign-32-1: Every signature is accepted

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized implementations, all three parameter sets (six wrappers)
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [LittleQ's PKC Forum post, 2026-09-23](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VT73TSZCRZVPPQDP3B4NBVVRRF36XVJ6/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §15](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

The internal `uvw_verify` routine computes the intended verification predicate. The API wrapper converts that result to `0` or `-1`, stores it in a local variable, and then unconditionally returns `0`.

Consequently, invalid signatures and modified messages that reach the final return are reported as valid. The modified-message witness reproduces on the 128- and 256-bit reference instances; some malformed signatures instead crash as described in `sign-32-2`. No cryptanalysis or signing query is required.

Follow-up analysis: [LittleQ reported on 2026-09-23](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VT73TSZCRZVPPQDP3B4NBVVRRF36XVJ6/) that all six submitted wrappers discard `uvw_verify`'s result. We source-checked the three optimized variants: each also computes `result` and unconditionally returns `0`. This extends the source-confirmed scope to both implementation families; the local runtime witness still uses reference builds, and 512-bit key generation was too slow for that witness.

This permits universal forgery through the submitted API and directly violates the claimed EUF-CMA security.

The wrapper must return the computed verification result rather than an unconditional success value. Tests must include invalid signatures and modified messages, not only valid KAT signatures.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-32
tools/ngcc_attack sig-accept-all sign-32/lib/libUVW-128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-32-2: An all-zero signature crashes two verifier instances

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: UVW-128 and UVW-256 reference implementations
Discovery: Trivial
Exploitation: Unauthenticated denial of service
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Direct verifier calls with a correctly sized all-zero signature crash the UVW-128 and UVW-256 implementations while deserializing or processing the malformed response. Signature verification is normally exposed to unauthenticated input, so this is a remotely triggerable denial of service independent of the universal-forgery return-value error in `sign-32-1`.

The unconditional-success wrapper hides ordinary nonzero verification results, but it cannot make a memory fault safe. Verification must validate every decoded length, index, and object before use and return rejection for malformed encodings.

### Reproducing

Run either affected instance through the guarded verifier driver:

```sh
tools/ngcc_attack sig-accept-all sign-32/lib/libUVW-128.so
```

Its verdict records `all-zero signature CRASHED the verifier` instead of a normal rejection. UVW-512 did not reproduce this crash and is not included in this finding.

## sign-32-3: Pair-correlated signatures recover an equivalent UVW-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: UVW-128, -256, and -512 specify the forced-pair sampler; practical recovery was demonstrated only for UVW-128
Discovery: Non-trivial
Exploitation: 300 known-message signatures; public recovery and one forgery in about one minute after collection
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-27
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SDUWEI2UT7BAEIDNVKTSMJF3YYJXUDFQ/)

The UVW specification samples the support as paired nonzero coordinates in Algorithm 5 step 3 (p. 10), maps that structured vector through the long-term secret monomial transformation in Algorithm 6 steps 16–18 (p. 13), and verifies its public syndrome and weight in Algorithm 8 (p. 14). This contradicts the p. 10 claim that the result is indistinguishable from a random large-weight vector: the hidden pairing is preserved for the lifetime of the key. The three sets use the same construction with `r1 = 3250`, 3167, and 6434, respectively.

From 300 known-message UVW-128 signatures, the released attack identifies enough high-confidence pairs to span a 1,600-dimensional public subspace; quotienting the 9,700 public columns by that subspace recovers all 4,850 hidden pairs and their relative scales. The recovered structure supplies an equivalent decoder and a fresh-message signature satisfying the intended weight-8,633 verification equation.

We independently replayed the public evidence: the attack recomputed its candidates from 300 public error vectors, obtained rank 1,600, recovered 4,850/4,850 pairs, constructed the equivalent decoder, and produced the exact 1,244-byte API signature. The intended `uvw_verify` predicate accepted it and rejected the same signature on a changed message. The forged signature therefore passes the intended verification predicate. The released experiment covers one fixed UVW-128 key, so no key-averaged success probability or practical recovery claim for UVW-256 or UVW-512 is made.

### Reproducing

```sh
sign-32/reproduce_pair_leakage_forgery.sh
```

The wrapper downloads and hash-checks Feussner's [package at commit `91f2ddf`](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/91f2ddf0590a24ad39afc2ce2ee4f2627ec54726/UVW), compiles the public recovery against the frozen local UVW source, and recomputes the public candidate list. It checks the recovered rank and pair set, fresh-message acceptance, changed-message rejection and exact API encoding. The likelihood scores are floating-point values, so the wrapper intentionally does not require a byte-identical score table across NumPy and BLAS versions. It needs Python with NumPy; regenerating the 300 signatures is documented in the pinned package but is not part of this approximately one-minute replay.

## sign-32-4: UVW-Sign resets the external DRBG for deterministic matrix expansion

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: UVW-128, -256 and -512 reference implementations
Discovery: Trivial
Exploitation: Signing and verification depend on the particular external RBG stream; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

`generate_f3_matrix` builds a local seed-and-nonce value, resets an external `DRNG_ctx`, and draws the matrix from it (`SIG_AlgorithmInstance.c:106–123`). Key generation, signing and verification all regenerate protocol matrices through this path. Their agreement therefore depends on the exact ICCS DRBG mapping rather than on a scheme-defined XOF.

The specification defines this expander itself, a PRNG "constructed based on the Chinese national standard SM3-DRNG" with an explicit seed-and-nonce input and conversion to F3 elements (§1.5, physical p. 12); calling that internal expander a PRNG is only a labeling matter. The defect is in the code, which wires the expander to the external ICCS RBG interface (`drng.c`, identical to the supplied API copy) instead of building it as an internal function. The three archived implementations are self-consistent. This is a Low interoperability dependency; no additional forgery is claimed.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id sign-32-4
```
