<!-- synchronized report: kem-08/report.md -->
Candidate: BW-KEM
Family: Lattice-based KEM
Archive: [BW-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BW-KEM.zip) (SHA-256: `a1f8a079df7d55576209f45fcf00afd700fc60c0b18d758d572585ccea594ae3`)

## kem-08-1: C128 decapsulation branches on decrypted coefficients

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: BW_KEM_C128 reference implementation
Discovery: Trivial
Exploitation: Secret-dependent branch trace before ciphertext validation; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23
Follow-up source: [BW-KEM team's confirmation and fix](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SRZRQZCBXGYWB4IFIMUWO6EFETFPRRYP/)

Decapsulation computes `mp = v - sᵀu` from the recipient secret and chosen ciphertext (`indcpa.c:321-331`), then branches on the sign of each centered coefficient while converting it to a message (`poly.c:174-193`). GCC `-O2` retains a conditional `jns`; the FO comparison occurs later (`kem.c:155-170`). The same submitted routine is also embedded in the related AFS-KEX C128 implementation. This establishes secret-dependent control flow, not a measured remote oracle or a transferable KyberSlash key-recovery attack; see `constant_time.md`.

The BW-KEM team confirmed the branch and reports that its AVX2 path was already branch-free.

### Proposed fixes

The [BW-KEM team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SRZRQZCBXGYWB4IFIMUWO6EFETFPRRYP/) proposes mask-based arithmetic in the reference, ARM, performance-optimized, and resource-optimized C128 implementations. This section records the proposal without evaluating it.

### Reproducing

```sh
ref=kem-08/Implementations/Reference_Implementation/BW_KEM_C128
cc -O2 -std=c99 -DBWKEM128_INTERNAL_COMPAT -DBWKEM128_USE_ICCS_AUXFUNC \
  -I"$ref" -Iapi -S "$ref/poly.c" -o - |
  sed -n '/bwkem128_poly_tomsg:/,/\.size[[:space:]]*bwkem128_poly_tomsg/p' |
  grep -E '\bjns\b'
```

The source trace and compiled branch are reproducible; no timing-based extraction is claimed.

## kem-08-2: AVX2 Barnes–Wall decoders branch on decrypted values

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Resource-optimized AVX2 BW_KEM_C256 and C512; performance- and resource-optimized AVX2 BW_KEM_C128. The performance-optimized C256 and C512 trees extract bits with `pext`
Discovery: Moderate
Exploitation: Local branch trace of the decoded message bits, or of one parity per decoded block, before ciphertext validation; no extraction demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
The resource-optimized C256 and C512 decoders turn the decoded lattice point into message bits with `extract_masked_bits_u64`, which loops over a constant mask and executes `if ((value & lowest_mask_bit) != 0)` for each bit (`BWcoding.c:9–25`, called at `:80`). `value` is the decoded form of `v − sᵀu`, so the branch outcomes are the message bits recovered with the private key. Decapsulation reaches this before the re-encryption check. The submitted flags are `-Os -march=x86-64 -mavx2`.

Both AVX2 C128 trees decide between two candidate decodings with `if(xor_sum)`, the parity of four hard decisions on the same secret-dependent value (`BWcoding.c:75`).

A branch-trace observer of one decapsulation therefore reads the decoded message, from which the shared secret follows, or one parity bit per block for C128. No timing oracle or extraction was built. The performance-optimized C256 and C512 trees use `_pext_u64` at the same point and have no such branch.

Constant-time fix (easy, hence Low): build the result with shifts of the masked bit, or select with a mask.

### Reproducing

```sh
d=kem-08/Implementations/Optimized_Implementation
sed -n '9,25p' "$d/resource-optimized/BW_KEM_C256_AVX2/BWcoding.c"
grep -n 'if(xor_sum)' "$d"/*/BW_KEM_C128_AVX2/BWcoding.c
grep -n '_pext_u64' "$d/performance-optimized/BW_KEM_C256_AVX2/BWcoding.c"
```

This is a source witness; the last command shows the branch-free control.

## kem-08-3: The API wrapper returns a decapsulation-failure code

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: BW_KEM_C128, C256 and C512; the `KEM_AlgorithmInstance.c` wrapper in the reference, AVX2 and ARM implementations
Discovery: Trivial
Exploitation: Ciphertext-validity oracle through the public return value; no standalone IND-CCA break demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

BW-KEM is specified with an implicit-rejection Fujisaki–Okamoto transform: decapsulation of an invalid ciphertext returns a pseudorandom key and no failure symbol (§4.2). The inner `crypto_kem_dec` does this with a constant-time select. The contest wrapper then undoes it: after `cmov(ss, kr, KYBER_SSBYTES, (uint8_t)!fail)` it executes `if (fail != 0) return KEM_API_DECAP_FAILURE;` (`KEM_AlgorithmInstance.c:119–123` in reference C128; the same statement is in every wrapper).

A modified ciphertext of the correct size therefore reports its invalidity through the return value and through a branch on the comparison result. Explicit-rejection transforms can be secure, so this alone is not an IND-CCA break; the finding is that the submitted API contradicts the specified implicit-rejection contract.

### Reproducing

```sh
grep -rn --include=KEM_AlgorithmInstance.c -B3 'return KEM_API_DECAP_FAILURE' \
  kem-08/Implementations/Reference_Implementation/BW_KEM_C128
```

This is a source witness. The listing shows the select followed by the failure return in `kem_dec`.
