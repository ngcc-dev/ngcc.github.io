<!-- synchronized report: kem-01/report.md -->
Candidate: Aigis-Enc+
Family: Lattice (Module-LWE)
Archive: [Aigis-Enc+.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Aigis-Enc%2B.zip) (SHA-256: `1c053133175cd189fd9f0e058bde684168f55a6fc3871de2a755404a08990186`)

## kem-01-1: Ineffective implicit rejection breaks IND-CCA security

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All three parameter sets in the reference, AVX2, NEON and AArch64 trees (the AVX2 trees were run; NEON and AArch64 by source)
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §7](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

Changing a ciphertext bit frequently leaves the decapsulated shared secret unchanged. An exhaustive sweep of Aigis-enc1 found that 5,632 of 7,168 single-bit ciphertext changes return the original shared secret. The same defect was reproduced in the other two parameter sets.

`mkem_dec` writes the candidate valid secret to the output before checking the re-encrypted ciphertext. On failure, the intended constant-time replacement writes into the wrong buffer, leaving the already-returned candidate secret untouched. Rejection is therefore ineffective.

An attacker given a challenge ciphertext and candidate challenge key can modify the ciphertext, decapsulate it through the allowed CCA oracle, and compare the result with the candidate key. Retention identifies the real encapsulated key and provides a direct IND-CCA distinguisher. This violates the claimed IND-CCA security at every submitted level.

Extended on 2026-10-17: the optimized and additional implementations contain the same `mkem_dec` sequence. In `Optimized_Implementation/avx2/Aigis-Enc+-{I,II,III}/kem.c`, line 71 copies the candidate key to `ss`, and line 80 applies `cmov(buf, buf2, SEED_BYTES, fail)` to the local `buf`. The NEON and AArch64 trees under `Additional_Implementation/` have the same lines 71 and 80. Unmodified AVX2 builds returned the challenge key for 5,632 of 7,168, 11,108 of 13,312 and 24,439 of 28,672 single-bit ciphertext changes at the three levels. The exact counts depend on the key pair. Honest decapsulation matched, and a second encapsulation gave a different key. The NEON and AArch64 trees were checked by source only and were not run.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-01
tools/ngcc_attack kem-ct-flip kem-01/lib/libAigis-enc1.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

To check the AVX2 trees, run:

```sh
sh kem-01/reproduce_avx2_retention.sh
```

The script copies the three AVX2 trees into a temporary directory and rebuilds
them from source, including the Keccak object that ships prebuilt. For each
level it sweeps every single-bit ciphertext change, with an honest-decapsulation
control and a second-encapsulation control, in about 30 seconds. It exits 77
when gcc or AVX2/BMI2 support is missing.

## kem-01-2: Rejection reads a secret before the secret-key object

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Every rejected ciphertext triggers an out-of-bounds read; no disclosure or control-flow impact demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The rejection path reads its fallback secret from `sk - SEED_BYTES`, before the start of the caller's secret-key object. Key generation stores that value at `sk + SK_BYTES - SEED_BYTES`. All three submitted `kem.c` files contain the same pointer error.

This is undefined behavior on every rejected ciphertext. Another assignment error in the submitted decapsulation path prevents the resulting fallback value from replacing the candidate shared secret. Correcting only that assignment would expose this second defect: rejection would derive its output from unrelated memory rather than the secret value stored in the key. The archived behavior is an out-of-bounds read, with no memory disclosure or control-flow impact demonstrated, hence Low.

The implementation must read the final `SEED_BYTES` of the secret-key object and must validate this repair independently of the separate fallback-selection error.

### Reproducing

The defect is directly visible in each reference implementation's `kem.c`: `mkem_dec` passes `sk - SEED_BYTES` to `hash_g`, while `mkem_keygen` stores the rejection secret at `sk + SK_BYTES - SEED_BYTES`.

## kem-01-3: The external DRBG is used as a KDF

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Aigis-Enc+-I, -II and -III ICCS reference implementations
Discovery: Trivial
Exploitation: Replacing the external RBG changes deterministic matrix expansion and breaks interoperability; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

Under `USE_NICCS_API`, `kdf_init` resets an ICCS `DRNG_ctx` from its input and `kdf_squeezeblocks` reads the resulting stream (`hashkdf.c:91–98`). Matrix generation calls this interface from public seeds (`gen_a.c:50–63`). Thus a nominally external RBG supplies a deterministic KDF whose exact byte stream is part of the algorithm. A different secure RBG need not reproduce it.

The shipped `drng.c` makes the three implementations work and this is not a cryptanalytic break. The defect is the unstated seed-to-stream dependency; it should be a scheme-defined XOF/KDF.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-01-3
```

## kem-01-4: Deterministic encapsulation overflows its key buffer and derives the wrong secret

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: `mdkem_enc` in reference and aarch64 implementations at all three levels; avx2 and neon allocate the correct `2*SEED_BYTES`
Discovery: Trivial
Exploitation: Deterministic encapsulation and decapsulation derive different shared secrets; a fixed-length stack write occurs; no attacker-controlled corruption shown
Credit: Kr0emer and Chen Peng (陈鹏); corrected overflow localization by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-19
Original source: [NGCC harness issue 24](https://github.com/ngcc-dev/ngcc-harness/issues/24)

Validated and corrected on 2026-10-20. In the reference and aarch64 trees, `mdkem_enc` allocates `kr[SEED_BYTES]`, then calls `Hash2(kr, buf, 2*SEED_BYTES)` (`kem.c:40–52`). For Aigis-Enc+-I, `Hash2` is `hash256` and writes 32 bytes into the 16-byte `kr`; the subsequent encryption also reads `kr + SEED_BYTES`. The analogous output is twice the allocated size in -II and -III. The avx2 and neon trees instead allocate `kr[2*SEED_BYTES]`. The original issue attributed the write to the earlier `Hash(buf + SEED_BYTES, pk, PK_BYTES)` call, but that call writes only `SEED_BYTES` output bytes; its third argument is the input length.

In our Aigis-Enc+-I replay, AddressSanitizer reports a stack-buffer overflow, and the uninstrumented deterministic path yields a different shared secret from decapsulation. The ordinary randomized encapsulation round trip agrees. The helper is declared in `api.h` but is not part of the NGCC uniform KEM ABI or called by the submitted KAT path. The hash write has a fixed length, not an attacker-controlled size. This limited API defect warrants Low; no memory disclosure, control-flow impact, or IND-CCA break is demonstrated.

### Reproducing

```sh
python3 kem-01/reproduce_mdkem_overflow.py
```

The wrapper builds the frozen level-I reference source with `-DUSE_SHA3`, the submitted speed-test configuration, in a temporary directory. It requires an ASan write failure and checks deterministic mismatch with a normal-path agreement control. The KAT build uses `-DUSE_NICCS_API`; the undersized allocation is independent of that hash backend. The other levels and the aarch64/avx2/neon allocations were source-inspected, not run.
