<!-- synchronized report: kem-13/report.md -->
Candidate: DKEM (Ding Key Encapsulation)
Family: Lattice (Module-LWE)
Archive: [DKEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DKEM.zip) (SHA-256: `862f40ba424253bae7fadbc9c2f54a568b77e0f97fba4728c5fd1e4e826dddc7`)

## kem-13-1: DKEM's rejection key does not bind the full ciphertext

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All DKEM parameter sets and submitted implementation families
Discovery: Trivial
Exploitation: Rejected ciphertexts sharing `c2` share a key; no IND-CCA or shared-secret recovery attack shown
Credit: Jieyu Zheng (GitHub @zhengjieyu)
Date: 2026-09-25
Original source: [ngcc-harness issue #16](https://github.com/ngcc-dev/ngcc-harness/issues/16)

Specification Algorithm 16 derives the rejection key as `KDF(rej || c2)`, omitting the `c1` component of `ct = c1 || c2`. The twelve submitted `dkecca.c` copies do the same (`dkecca.c:109–111`). Thus distinct rejected ciphertexts with the same `c2` return the same key, violating full-ciphertext key binding. With access to decapsulation outputs, comparing a ciphertext's key to that of a changed-`c1` ciphertext also distinguishes acceptance from rejection, contrary to the specification's §5.3 claim that implicit rejection provides no validity signal. This does **not** establish an IND-CCA break or a way to recover an honest party's secret key or session key; the submitted IND-CCA proof explicitly models this `c2`-only rejection derivation.

### Reproducing

```sh
make -C api harness
make -C kem-13
python3 kem-13/reproduce_rejection_binding.py \
  kem-13/lib/libDKEM-128.so kem-13/lib/libDKEM-256.so \
  kem-13/lib/libDKEM-512.so
```

For each parameter set, the witness checks an honest encapsulation, two distinct rejected `c1` values with the same `c2` and identical decapsulation keys, and a changed-`c2` control with a different key. It exercises the archived reference implementation; the identical rejection derivation in optimized and additional sources was checked statically.

## kem-13-2: Malicious public key defeats DKEM's contributory key derivation

Severity: Medium
Status: Confirmed
Layer: Design
Affected: DKEM-128, DKEM-256, and DKEM-512
Discovery: Trivial
Exploitation: Fresh encapsulations to a malicious public key produce a repeated, predictable key; protocol impact depends on how the key is used
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

The specification's §3 says DKEM is “contributory by construction” because both parties affect the reconciled secret. This claim fails for an attacker-supplied public key whose polynomial vector is zero. In Algorithm 11, the sender's product with that vector vanishes; the remaining doubled, small error produces a zero reconciliation signal and an all-zero raw shared secret. Algorithm 14 and `dkecca.c` then derive the final key from that raw secret alone, so fresh sender coins and distinct ciphertexts all yield the same `KDF` output. The ciphertext's `c2` also exposes the coins because it XORs them with the zero raw secret. This holds for each submitted parameter set and does not depend on weaknesses of the placeholder hash functions.

The witness gives 64 distinct ciphertexts but one shared key across 64 encapsulations for each parameter set, versus 64 distinct keys with an honestly generated public key. For DKEM-128 and DKEM-256 the repeated key is exactly `sm3hash(256, 0^32)`. This is a malicious-public-key contributiveness and key-binding failure; it does not establish an IND-CCA break for honestly generated keys or show that a recipient accepts these ciphertexts under an honestly generated secret key. Including fresh sender input in the final key derivation would prevent this particular repeated-key outcome; any broader public-key or ciphertext binding claim needs its own analysis.

### Reproducing

```sh
make -C api harness
make -C kem-13
python3 kem-13/reproduce_malicious_key.py \
  kem-13/lib/libDKEM-128.so kem-13/lib/libDKEM-256.so \
  kem-13/lib/libDKEM-512.so
```

For each parameter set, the witness encapsulates 64 times to an honestly generated public key (control: 64 distinct keys) and 64 times to the same key with its polynomial vector zeroed and `rho` kept. It checks distinct ciphertexts and distinct `c2` values but a single key, and for 32-byte keys that the key equals `sm3hash(256, 0^32)`. The source-level trace, identical in all three `Reference_Implementation/DKEM-*` instances, is Algorithm 11's zero public vector, `dkecpa.c:174–186` (the sender's reconciled secret), `dke_utils.c:97–105,172–176` (signal and raw-secret extraction), and `dkecca.c:65–76` (the final key and `c2`).

## kem-13-3: A 16-bit NTT butterfly silently breaks honest DKEM-512 sessions

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: DKEM-512 scalar reference, NEON, Cortex-M4, and auto-detected natural-order AVX2 intrinsic paths; the official packed-assembly AVX2 build is unaffected
Discovery: Moderate
Exploitation: Honest encapsulation and decapsulation disagree about once per 2^11 trials; no key recovery demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-28
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GD3QWKLXKTRIRKCMKCOHTFRLBQN3REES/)
Follow-up source: [DKEM/DKEX/ADKEX team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NRJXWUW3IRBVMQZEGW3DNPUVK6PW7YLG/) and [Sun Shuzhou's recheck](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XCBIRRBK5PRUUSJ6OWVVCFC5B43UHLXS/)

Table 1 and §3.4 claim a DKEM-512 reconciliation-failure probability of at
most about `2^-167`. The scalar forward NTT instead stores both butterfly sums
in `int16_t` (`DKEM-512/ntt.c:78–88`). With `q = 7681`, legitimate lazy
intermediates can exceed the signed 16-bit range and wrap on the submitted
platform. The corrupted decapsulation transform then fails re-encapsulation
and selects the implicit-rejection key, but the API still returns success. Sun
reports an observed honest mismatch rate near `2^-11`; this also invalidates
the shipped implementation's §5.2.5 failure-boosting estimate. The `q = 3329`
DKEM-128 and -256 sets have substantially more headroom and are controls.

### Follow-up Analysis

The team confirms 12 mismatches in 20,000 and 21 in 40,000 scalar DKEM-512 sessions, as well as the same defect in the submitted NEON and Cortex-M4 backends. Its official packed-assembly AVX2 build reduces between layers and is unaffected. Sun's follow-up confirms the repair on those paths but reports 21 failures in 24,000 sessions through the natural-order AVX2 intrinsic chain selected by default when the sources are built without `DKE_NTT512_PACKED`; this is not the official optimized build. Instrumentation made every observed overflow/failure depend only on the public ciphertext, which supports limiting this finding to correctness rather than secret-key leakage.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/8e3417a) proposes Barrett-reducing all coefficients after the length-64 and length-8 forward-NTT layers in the reference and NEON code, and reducing between the two four-layer Cortex-M4 passes. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C api harness
make -C kem-13
python3 kem-13/reproduce_ntt_overflow.py \
  kem-13/lib/libDKEM-128.so kem-13/lib/libDKEM-256.so \
  kem-13/lib/libDKEM-512.so
```

With a fixed DRNG seed, the witness finds a silent DKEM-512 mismatch within
2,000 honest sessions while 3,000 sessions in each lower set agree. It checks
that `kem_dec` returns `0` on the mismatching session. This is a deterministic
failure witness, not an independent statistical estimate of the `2^-11` rate
or a failure-oracle key-recovery attack.

## kem-13-4: DKEM ignores input lengths before fixed-size reads

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: DKEM-128, -256, and -512 API implementations; runtime witness on the reference DKEM-128 decapsulator
Discovery: Trivial
Exploitation: Malformed-input out-of-bounds read and process termination; no disclosure demonstrated
Credit: DKEM / DKEX / ADKEX team
Date: 2026-10-01
Original source: [Team's PKC Forum follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HDVKBBLQ27XTZDNG5KU6BECX3Y4TT754/)

`kem_enc` discards `pk_len_bytes`, and `kem_dec` discards both `sk_len_bytes` and `ct_len_bytes`, before the implementation parses fixed-size objects (`KEM_AlgorithmInstance.c:39–55`). A caller-supplied truncated key or ciphertext is therefore read beyond its allocation. The team confirms the same pattern in every DKEM implementation and reports reproducing it with AddressSanitizer.

The local witness passes a one-byte-short honest ciphertext to the reference DKEM-128 decapsulator and requires an AddressSanitizer heap out-of-bounds read. It demonstrates no returned memory disclosure, write, or control-flow effect, so the finding is Low.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/c6c2faa) proposes validating every input length before reading input or drawing randomness and returning `-2` for a mismatch. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kem-13 reproduce-truncated
```
