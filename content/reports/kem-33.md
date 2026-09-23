<!-- synchronized report: kem-33/report.md -->
Candidate: QUBE
Family: Code-based
Archive: [QUBE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QUBE.zip) (SHA-256: `f5eedd8a4bf786cd5a56a21f2c7ad5cf3307939a1bf0aeca5041920067880396`)

Reference-KAT note: `make -C kem-33 test` reports four mismatches and one
missing KAT because the submitted top-level vectors do not match the submitted
reference tree; this is independent of the timing findings below. The harness
documents the submitted reference/in-tree-vector comparison in `kem-33/README.md`.

## kem-33-1: Decapsulation re-expands the private seed with a variable-length sampler

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: QUBE reference KEM decapsulation; demonstrated on QUBE-256
Discovery: Trivial
Exploitation: Secret-seed-dependent execution trace; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`crypto_kem_dec` calls `qube_pke_decrypt`, which regenerates the private support from the persistent PKE seed on every decapsulation. `vect_sample_fixed_weight` draws until it has enough distinct positions and branches on rejected or duplicate positions (`src/ref/vector.c:89-108`). Its work therefore depends on the secret seed even for a fixed public ciphertext. The final FO comparison does not remove this timing dependence. No key-recovery attack from the trace is claimed; see `constant_time.md`.

Follow-up analysis: FO re-encryption also samples from coins derived from recovered `m_prime` (`src/common/kem.c:155-160`, `src/ref/qube.c:124-136`). This resembles the setting of [Guo et al.](https://eprint.iacr.org/2021/1485.pdf), but their HQC/BIKE recovery attack has not been established for QUBE.

### Reproducing

The witness instruments only the submitted sampler's draw call, without changing its decisions. From the repository root:

```sh
ct_dir=$(mktemp -d)
ref=kem-33/Implementations/Reference_Implementation/qube-256
cc -std=c99 -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I "$ref/src/common" -I "$ref/src/common/qube-256" \
  -I "$ref/src/ref" -I "$ref/src/ref/qube-256" \
  -I "$ref/lib/api_pkc" -I "$ref" \
  -o "$ct_dir/repro" kem-33/reproduce_ct_sampler.c \
  "$ref/src/common/symmetric.c" "$ref/src/common/crypto_memset.c" \
  "$ref/lib/api_pkc/auxfunc.c"
"$ct_dir/repro"
```

It confirms different draw counts for two private seeds (254 versus 231 on this build). The source call chain is `src/common/kem.c:155` → `src/ref/qube.c:182-195` → `src/ref/vector.c:89-108`.

## kem-33-2: Decryption multiplication traverses secret support positions

Severity: Medium
Status: Probable
Layer: Side-channel
Affected: QUBE reference decapsulation; demonstrated in QUBE-256 source
Discovery: Moderate
Exploitation: Local branch/address trace tied to private support; full shared-secret recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

QUBE re-expands the private seed into `y_support`, then multiplies the public ciphertext polynomial by that support during every decapsulation (`src/ref/qube.c:182-192`). `ring_mul_by_support` passes each private position as a shift (`src/ref/gf2x.c:59-63`); the shift controls branches and output addresses in `xor_shifted`/`xor_linear_word` (`:14-25,44-57`). A fine-grained local trace can therefore depend on private support positions, beyond the public ciphertext. Recovering the entire support would enable PKE decryption and, for a valid ciphertext, shared-secret derivation, but no physical trace or full recovery is demonstrated; see `constant_time.md`.

### Reproducing

Inspect `src/common/kem.c:155`, `src/ref/qube.c:182-192`, and `src/ref/gf2x.c:14-25,44-63` under `Implementations/Reference_Implementation/qube-256/`. This source-level witness identifies the secret-to-address path, not a measured cache attack.
