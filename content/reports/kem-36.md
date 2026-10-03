<!-- synchronized report: kem-36/report.md -->
Candidate: TRIKE
Family: Code-based
Archive: [TRIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TRIKE.zip) (SHA-256: `03956a13fde3d402513bfcf9942f2b04fd23e98b01a3dc52b48938b9c89fe4d6`)

## kem-36-1: The specified TRIKE decoder rejects every tested honest ciphertext

Severity: High
Status: Confirmed
Layer: Design
Affected: TRIKE specification; all four implementations use a different rule
Discovery: Trivial
Exploitation: Trivial correctness failure for the specified algorithm
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Xiong and Wang's TRIKE analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/)

TRIKE's PDF defines the bit-flipping threshold as `max(Tnow,T′)`, repeats that return value in Algorithm 8, and explains that the decoder uses the larger threshold. Every submitted implementation instead computes `min(Tnow,T′)`.

The difference is decisive. In a paired whole-KEM test where the libraries differed only in this expression, the shipped `min` decoder recovered 1,000/1,000 honest TRIKE-2 shared secrets. The literal PDF `max` decoder recovered 0/1,000: the API still returned success, but every derived shared secret was wrong. Hence the specified scheme is nonfunctional, while the implementation and its KATs instantiate a materially different decoder. Any DFR claim must identify and analyze the actual rule.

### Follow-up Analysis

Zhenyu Xiong and Mingsheng Wang's [2026-09-30 PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/) identifies an independent defect in the same specified decoder: Algorithm 8 omits the original syndrome term when updating the syndrome, while the source retains it. This gives a second reason that the specified decoder differs from the implemented one; the post does not independently retest the `max`/`min` differential above and does not change this finding's classification.

### Reproducing

```sh
make -C kem-36 lib/libTRIKE-2.so
python3 security/trike_threshold_differential.py --trials 1000
```

The script builds an isolated copy with the literal PDF expression and compares both complete KEMs on identical deterministic trials.

## kem-36-2: The specified weak-key test rejects every key

Severity: Low
Status: Confirmed
Layer: Design
Affected: TRIKE specification, all parameter sets; submitted implementations use a different formula
Discovery: Trivial
Exploitation: Literal specified key generation never terminates; submitted code is unaffected
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's TRIKE analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/)

Appendix Algorithm 9 sums the squares of the distance multiplicities in both its intra-block and inter-block tests. For any secret block of weight `d`, the intra-block multiplicities sum to `C(d,2)`, so their squares sum to at least `C(d,2)`. The inter-block multiplicities sum to `d^2`, so their squares sum to at least `d^2`. These lower bounds already exceed Table 11's `s` and `s'` thresholds for every specified set. The literal algorithm therefore rejects every candidate key.

All submitted implementations instead weight a multiplicity `i` by `C(i,2)`, which is the collision count described in the surrounding prose. That code terminates, so this is a specification-level non-progress defect rather than a break of the archived executable implementations.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/) proposes replacing each squared multiplicity in Algorithm 9 with the binomial count `C(mu,2)`. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-36/reproduce_weak_key_test.py
```

The certificate checks all six specified parameter sets and verifies the distinct binomial formula in all eight submitted reference and optimized source trees.

## kem-36-3: Decapsulation fails to free the private h0 buffer

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All four reference and four optimized implementations
Discovery: Trivial
Exploitation: Repeated decapsulation exhausts process memory; no secret disclosure or cryptographic break demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's TRIKE analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/)

`kem_dec` allocates a padded buffer `h0`, copies the first private parity-check block into it, and never frees it. The function frees its other eleven heap buffers before returning. The omission is present in every submitted parameter set in both implementation families.

The reporters observed an AddressSanitizer direct leak and approximately 2,064 bytes retained per TRIKE-2 call and 16,400 bytes per TRIKE-7 or TRIKE-9 call. This supports resource exhaustion in a long-running decapsulation service, but neither memory disclosure nor control-flow impact is shown.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/) proposes adding `free(h0)` after `free(t0)` in each of the eight affected decapsulation functions. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-36/reproduce_implementation_issues.py
```

The static certificate isolates `kem_dec`, confirms the unmatched `h0` allocation, and checks that the other temporaries are freed in all eight source trees.

## kem-36-4: Boundary weak-key classes are omitted from the DFR bound

Severity: Medium
Status: Proof gap
Layer: Design
Affected: TRIKE weak-key rejection and DFR analysis, all parameter sets
Discovery: Moderate
Exploitation: The target-level failure bounds are not established for adjacent unfiltered key classes; no excessive DFR is demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's TRIKE analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/)

Appendix Tables 12–14 derive complete filtering only for weak-key classes at or beyond the selected boundary `m0`. For the adjacent unfiltered classes `m0-1`, the specification instead reports zero failures in `10^7` experiments for TRIKE-1/2/3/5 and `10^6` for TRIKE-7/9. Those experiments give only 95% upper confidence limits of about `2^-21.67` and `2^-18.35`; they do not establish failure probabilities at the claimed `2^-128` through `2^-512` scales.

This is an evidence gap, not evidence that the true DFR is as high as those confidence limits. In particular, zero observed failures supplies no lower bound on the boundary-class DFR and no concrete failure-oracle or key-recovery attack follows from the reported experiment.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/) proposes fitting the failure model separately for the boundary classes and including their density-weighted DFR in the total bound. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-36/reproduce_spec_proof_gaps.py
```

The certificate locates the two unfiltered-boundary statements, their experiment counts, and their confidence limits in the submitted PDF.

## kem-36-5: The weak-key reduction assumes the secret parity checks are public

Severity: Medium
Status: Proof gap
Layer: Design
Affected: TRIKE Theorem 4 and its claimed weak-key-rejection security loss
Discovery: Moderate
Exploitation: The stated reduction cannot test its required predicate from the actual public key; no IND-CCA attack demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's TRIKE analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/)

Normative KEM.KeyGen (Algorithm 4) publishes `pk = (sigma,r2)` and retains `(h0,h1,h2)` in the secret key. Theorem 4 nevertheless begins its reduction with “public key `pk = (h0,h1,h2)`” and has the reduction decide whether that tuple passes the private weak-key predicate. An IND-CCA instance for the actual scheme does not reveal those parity checks, so the described reduction cannot perform its first step.

Conditioning key generation on a rejection event of probability `rho` can still be related to the original distribution by a generic statistical-distance bound of order `rho`. The report does not claim the conditioned scheme is insecure; it records that the specification's exact multiplicative reduction and its quoted negligible bit loss are not proved by the stated argument.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/) proposes dropping Theorem 4 and accounting for weak keys on the DFR side instead. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-36/reproduce_spec_proof_gaps.py
```

The certificate checks both the actual public-key assignment in Algorithm 4 and the incompatible public-key assumption in Theorem 4.

## kem-36-6: Decapsulation addresses depend on the secret support

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: All four reference and four optimized implementations
Discovery: Moderate
Exploitation: Repeated fine-grained secret-address dependence in decapsulation; no observation trace or key recovery demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's TRIKE analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/)

Decapsulation copies the sparse secret supports `h0_idx`, `h1_idx`, and `h2_idx` from the secret key into the decoder. The reference `calc_upc_block` then computes `idx_to = (i + idx[k]) mod r` and reads `s[idx_to/8]`; its memory addresses therefore expose the support positions repeatedly throughout decoding. The optimized rotation path likewise derives its load offsets from secret shifts. The early-exit comparison used by some paths adds a smaller timing dependency.

This contradicts the specification's statement that the reference implementation was designed to execute in constant time and that the optimized implementation preserves constant-time behavior (p. 12). The finding confirms the address dependence only; the reporters did not capture a cache or power trace and did not recover a key.

Constant-time fix (moderate, hence Medium): replace secret-indexed rotations with an oblivious rotation, such as a masked barrel shifter or a BIKE-style constant-time decoder, and use a masked ciphertext comparison. This is a substantial decoder rewrite, but published techniques exist.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6LRD73BAIXBHGRSZRC7Z7XUMNGGVDY27/) proposes register-level rotation for the secret-support operations and a masked ciphertext comparison. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-36/reproduce_implementation_issues.py
```

The certificate traces the index from the secret key into the syndrome address in every submitted source tree.

## kem-36-7: TRIKE shares the generic unsalted-FO multi-ciphertext loss, no TRIKE-specific weakness

Severity: Info
Status: Confirmed
Layer: Design
Affected: TRIKE-2, -5, -7 and -9 specification and implementations, in common with other unsalted deterministic FO KEMs
Discovery: Moderate
Exploitation: None specific to TRIKE; with T observed ciphertexts under one key, one shared secret is found in about 2^l/T public encapsulations, which does not break the required single-challenge IND-CCA2 game
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-10-03
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MM2JSFZV6NOP4XH3EKBO3RGK4R5LVGPO/)

Reference: [Andreeva et al., ePrint 2025/343](https://eprint.iacr.org/2025/343)

TRIKE encapsulation samples one `l`-bit message and deterministically derives both ciphertext and shared secret from it and the public key, without a salt (Algorithm 5, physical p. 7; `KEM_AlgorithmInstance.c:242–273`). Given `T` ciphertext fingerprints under one key, public re-encapsulation therefore recovers one message and its shared secret after about `2^l/(T+1)` trials; for `T=2^32` this is about `2^224` encapsulations for TRIKE-5 and `2^480` for TRIKE-9. The scaled witness confirms the mechanism on the submitted code.

This is recorded for information. The amortization is the generic multi-ciphertext loss of any unsalted deterministic FO KEM whose message length equals its target, a property shared by many submissions and by standardized designs. It is not a break of the single-challenge IND-CCA2 game required by the call, and the `2^80` evaluation budget limits chosen decapsulation queries rather than the number of honest ciphertexts available to such a passive search. TRIKE's specification makes no multi-target claim beyond its IND-CCA2 statement and adds nothing that would make the loss worse than in the generic case. A public salt, or a message longer than the target level, would prevent the amortization.

### Reproducing

```sh
make -C kem-36 reproduce-multitarget
python3 kem-36/reproduce_multitarget_bounds.py
```

The native scaled witness links the unmodified submitted encapsulation and decapsulation code, forces only the small model message, checks the single global RNG read, and requires the recovered key to match both parties. The certificate checks the full-size source paths and the `2^l/T` accounting; the full searches are extrapolated.

## kem-36-8: TRIKE resets the external DRBG for deterministic re-encryption

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: TRIKE-2, -5, -7 and -9 reference implementations
Discovery: Trivial
Exploitation: Encapsulation and FO re-encryption agree only for the particular external RBG stream; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

`generate_error_vector` hashes `msg || r2`, resets a local external `DRNG_ctx` from that value, and draws the deterministic error vector (`sample.c:230–244`). Encapsulation and decapsulation both call it to make the FO re-encryption comparison (`KEM_AlgorithmInstance.c:252,353`). This is XOF/PRG functionality: changing the RBG mapping makes honest ciphertexts fail verification.

The bundled `drng.c` gives a working frozen implementation. The Low defect is making correctness depend on a nominally external RBG rather than a specified deterministic expander.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-36-8
```
