<!-- synchronized report: kem-15/report.md -->
Candidate: FLIT
Family: Lattice (NTRU-like KEM)
Archive: [FLIT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/FLIT.zip) (SHA-256: `6c560f434b347fbac8334f55b9ba2838cb1cf885d5aa25e95acb66ed6c6de0fe`)

## kem-15-1: FLIT512 reference and optimized implementations silently derive different keys

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted FLIT512 reference and AVX2 implementations
Discovery: Trivial
Exploitation: Mixing the two official implementations causes silent session-key mismatch
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-29
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UJMEBKKD3OZ3QHPHEARB2WBINLVX5RR7/)

The FLIT512 AVX2 `poly_compress_and_pack` omits the reference implementation's `& 0x1FF` reduction in its nine-bit compression branch (`poly.c:299–331`). For coefficients 3326–3328 the reciprocal quotient is 512; the reference maps it to zero, while the optimized packer lets bit 9 spill into the next field.

Both implementations self-verify. With the same seed they also generate identical public and secret keys, but their ciphertext and shared secret differ. Each cross-decapsulation returns `0` while deriving a key different from the sender's; the API uses `0` for both its acceptance and implicit-rejection paths, so this value does not show which path ran. Across the ten submitted KAT seeds, ciphertext and shared secret differ in eight records; the local fresh-seed witness below produces a one-byte ciphertext difference and silent mismatch in both directions.

This is a limited interoperability and correctness failure, not a confidentiality break, hence Low.

Follow-up response: the [FLIT team's 2026-09-29 post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VRUXVADZDQ6DMCIH2BPPGKOF54UOFAOI/) confirms the archived package's interoperability behavior and the missing mask as its cause. The team says it had independently identified the defect before the public report.

### Proposed fixes

The [FLIT team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VRUXVADZDQ6DMCIH2BPPGKOF54UOFAOI/) proposes adding `& 0x1FF` in the optimized nine-bit compression branch and points to its [updated implementation](https://github.com/MathEternal/FLIT-NGCC). This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-15/reproduce_interop.py
```

The script builds both archived implementations in a temporary directory, exercises their submitted APIs with one common seed, checks self-decapsulation controls, and prints `CONFIRMED kem-15-1` only when both cross-decapsulations silently derive the wrong key.

## kem-15-2: Optimized equality check accepts invalid ciphertexts and exposes a plaintext-checking oracle

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All five AVX2 trees: FLIT128/256/512 and FIPS202 OPT128/256
Discovery: Moderate
Exploitation: Near-total bypass of re-encryption rejection on unrelated ciphertexts and a plaintext-checking oracle; full key recovery not executed
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KP5VT25RVLVRBBJ7XFPTNMBSZV6PIPEN/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/b1b7e429d4bf9673f2040f3e951df827a6d0dbe6/flit-opt-verify-fo-bypass)
Follow-up source: [FLIT team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/35QW2XAG22E5OWR3HRRVTD5HAKEDITQH/)

The optimized equality check folds ciphertext differences into a 64-bit word and returns `(-(int64_t)r)>>63` (`verify.c:18–38`). This is not a nonzero test and also invokes signed-overflow undefined behavior at `r=2^63`. In our GCC 15.2 build it reported equality for about 3.8% of ciphertexts with one to four random bit changes; reference and patched controls rejected all of them. Bit 63 of the OR-folded difference is set for essentially every ciphertext that decrypts to a different message, so rejection fails far more broadly than the low-bit edit rate suggests. A direct 2,000-pair comparison of unrelated 1 KiB inputs found 2,000 false equalities, while the reference rejected all 2,000. The exact frequency and edge behavior depend on the compiler.

The result feeds the Fujisaki–Okamoto conditional move (`kem.c:107–126` in the FLIT128/256/512 optimized trees; 106–125 in FIPS202 OPT128/256). When an invalid ciphertext is misclassified, decapsulation returns the accept-path KDF value. For five such ciphertexts the witness recomputed that value from the public key, ciphertext, and correct plaintext guess, while a wrong guess failed. The mismatch return is `-1` rather than `1`, so the AVX2 conditional move's byte mask becomes `0x01`; even correctly rejected ciphertexts replace only bit 0 of each pre-key byte with the rejection secret. The witness establishes a plaintext-checking oracle, but no FLIT key-recovery or IND-CCA distinguisher has been completed, so the finding is High.

### Proposed fixes

The original post proposes replacing the return expression with a constant-time 64-bit nonzero fold whose result is exactly 0 or 1. The [FLIT team reports](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/35QW2XAG22E5OWR3HRRVTD5HAKEDITQH/) applying `return (int)((r | (UINT64_C(0) - r)) >> 63);` in all five affected trees, states that this also restores the conditional move, and reports that the corrected trees pass its rejection-path regression tests with unchanged KATs. The change is committed to the team's [GitHub repository](https://github.com/MathEternal/FLIT-NGCC); the frozen submission is unchanged. This records the fix without evaluating it.

### Reproducing

```sh
./kem-15/reproduce_fo_bypass.sh
python3 kem-15/reproduce_random_compare.py
```

## kem-15-3: The FIPS202 variants generate predictable keys because their RNG is never seeded

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All four submitted additional FIPS202 REF/OPT128 and REF/OPT256 implementations; the primary SM3 variants are not affected by this RNG path
Discovery: Trivial
Exploitation: A fresh process's first key pair and encapsulation are reproducible from public source, permitting private-key reconstruction and decapsulation
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

All four FIPS202 trees link their own `rng.c` in their normal Makefile builds (`Implementations/README.md:83`). It initializes `rng_seed` to 32 zero bytes and `rng_ctr` to zero; `randombytes` draws SHAKE256 from that fixed seed and counter (`rng.c:16–40`). Their PKE key generation, KEM fallback-key generation and encapsulation call this `randombytes` (`indcpa.c:33`, `kem.c:32,59`). Nothing in the submitted KEM API calls `randombytes_init`. The KAT driver seeds a *different* object, `drng_algorithm` (`KAT_KEM.c:103–108`), so even its varying test seeds do not seed the RNG that key generation uses.

Consequently an attacker can start a fresh copy of the submitted FIPS202 implementation, regenerate a victim's first public/secret key pair, and decapsulate ciphertexts addressed to that public key. This violates the 128- and 256-bit KEM security targets, without relying on a weak entropy source or on KAT-only behavior. The finding is limited to these additional implementations: explicitly calling the separate `randombytes_init` function before use changes their output, but that call is not part of the submitted KEM API.

### Reproducing

```sh
python3 kem-15/reproduce_fips202_unseeded_rng.py
```

The witness builds each of the four frozen trees and runs its KEM API in separate processes after two different external-DRBG seeds. It requires identical key pairs, ciphertexts and shared secrets in those runs. As a negative control, explicit initialization of the internal RNG with different seeds must change the outputs.
