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

Constant-time fix (moderate, hence Medium): store the expanded support in the private key instead of re-deriving it on every decapsulation, which changes the key format and storage, or sample it with a fixed number of draws and constant-time duplicate handling. Both are well-known techniques with moderate cost.

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
Status: Confirmed
Layer: Side-channel
Affected: QUBE reference decapsulation; demonstrated in QUBE-256 source
Discovery: Moderate
Exploitation: Local branch/address trace tied to private support; full shared-secret recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

QUBE re-expands the private seed into `y_support`, then multiplies the public ciphertext polynomial by that support during every decapsulation (`src/ref/qube.c:182-192`). `ring_mul_by_support` passes each private position as a shift (`src/ref/gf2x.c:59-63`); the shift controls branches and output addresses in `xor_shifted`/`xor_linear_word` (`:14-25,44-57`). A fine-grained local trace can therefore depend on private support positions, beyond the public ciphertext. Recovering the entire support would enable PKE decryption and, for a valid ciphertext, shared-secret derivation, but no physical trace or full recovery is demonstrated; see `constant_time.md`.

Constant-time fix (moderate, hence Medium): multiply by the private support with a dense constant-time polynomial multiplication, or rotate by each position with a constant-time barrel shifter. Both are well-known techniques, but they replace the sparse fast path at moderate cost.

### Reproducing

Inspect `src/common/kem.c:155`, `src/ref/qube.c:182-192`, and `src/ref/gf2x.c:14-25,44-63` under `Implementations/Reference_Implementation/qube-256/`. This source-level witness identifies the secret-to-address path, not a measured cache attack.

## kem-33-3: The optimized API generates predictable keys and encapsulations

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Optimized QUBE-128, QUBE-256, QUBE-384 and QUBE-512; reference implementation unaffected
Discovery: Trivial
Exploitation: A fresh-process key-generation call reproduces the complete decapsulation key; encapsulation under an honest public key reproduces the ciphertext and shared secret
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-03
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/RFAWJMFS3YHSQG4HMPKOCVYLX7BZK3YX/)

The optimized API draws all key-generation and encapsulation randomness from a file-scope SHAKE context (`src/common/symmetric.c:15,27–45`; `src/common/kem.c:43–58,125–157`). That context is zero-initialized, and `prng_init` is called only by the benchmark and standalone test, never by the API wrapper. Seeding the separate ICCS DRNG therefore has no effect: every fresh process starts from the same key, message and salt stream.

We reproduced complete public/secret-key recovery and sender-side ciphertext/session-key prediction on all four optimized sets. A corrected-PRNG control and the reference implementation both vary across seeds.

### Reproducing

The quick certificate checks the call graph and exercises the raw stream:

```sh
python3 kem-33/reproduce_unseeded_optimized.py
```

The full replay downloads a hash-pinned artifact, builds against the local submitted trees, and asserts both recovery paths and controls:

```sh
JOBS=8 kem-33/reproduce_unseeded_optimized.sh
```

## kem-33-4: The optimized FO check compares word counts as byte counts

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Optimized QUBE-128, QUBE-256, QUBE-384 and QUBE-512 (`qube-1/3/4/5`); reference implementation unaffected
Discovery: Trivial
Exploitation: One decapsulation query on a ciphertext with a bit flipped in the unchecked tail of `u` or `v` returns the challenge shared key on all four optimized sets; no private-key recovery was attempted
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Decapsulation (spec Fig. 6, p. 10) re-encrypts the decrypted message and returns `k′` only if the re-encryption equals the received ciphertext, `c′ = c`; otherwise it returns the rejection key `k∗`. The optimized `crypto_kem_dec` performs this check with `vect_compare(c_kem_t.c_pke.u, c_kem_prime_t.c_pke.u, VEC_N_256_SIZE_64)` and the same for `v` with `VEC_N1N2_256_SIZE_64` (`Implementations/Optimized_Implementation/src/common/kem.c:257–258`). `vect_compare` treats its size argument as a byte count (`src/x86/vector.c:283–290`), but the two macros are counts of 64-bit words for the 256-bit-aligned buffers (`src/x86/qube-*/parameters.h:48–49`). Only the salt comparison (`kem.c:259`) covers its whole field.

The comparison therefore covers only a short prefix of each component: `u` 256 of 1,639 bytes and `v` 204 of 1,632 bytes at QUBE-128; 768/5,207 and 660/5,280 at QUBE-256; 1,536/10,345 and 1,344/10,752 at QUBE-384; and 2,304/16,982 and 2,272/18,176 at QUBE-512. The returned key `k′` is derived from `m′`, `H(pk)` and the salt only (`kem.c:236–241`), and the concatenated Reed–Muller/Reed–Solomon decoder absorbs the error introduced by a change in the unchecked tail, so decryption still returns the encapsulated message. A modified ciphertext is then accepted and yields the honest shared key.

This gives a one-query IND-CCA2 distinguisher: given a challenge `(c∗, K)`, the adversary flips one bit in the unchecked tail of `u` or `v` of `c∗` and asks for its decapsulation, which is a legal query because the ciphertext differs from `c∗`, and compares the answer with `K`. The same acceptance also makes ciphertexts malleable. Because the decapsulation output now shows whether a tail modification changed the decrypted message, it may also serve as a reaction oracle on the private support; that was not attempted.

All four built optimized parameter sets are affected. The unbuilt `qube-6/7/8` directories share `kem.c` and define the macros the same way. The reference implementation compares the full ciphertext and rejects the same modifications.

### Reproducing

```sh
sh kem-33/reproduce_opt_partial_compare.sh
```

The script checks the source lines and prints each set's compared prefix sizes. It then builds the submitted optimized tree in a temporary directory and, for each of the four sets, confirms over 10 fresh key pairs (50 with `NGCC_LONG=1`) that a single bit flipped in the `u` tail and in the `v` tail keeps the honest key. Its controls are flips in the compared prefixes and the salt, and the same tail flips against the prebuilt reference libraries; all of these change the key. Because the optimized API never seeds its SHAKE PRNG, the harness seeds it through `prng_init` with fresh randomness, as the submitted `tests/qube-test.c` does. The run takes about 40 seconds, most of it compilation, and is skipped (exit 77) without gcc or AVX2.
