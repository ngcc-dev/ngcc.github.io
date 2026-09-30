<!-- synchronized report: kem-37/report.md -->
Candidate: TriQ-KEM
Family: Code-based
Archive: [TriQ-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TriQ-KEM.zip) (SHA-256: `1e4b96e7a849c95b4a6511c5739be9e0b4adf19b00195c2c0ce14f66be316876`)

## kem-37-1: Decapsulation re-expands its private support with variable work

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: TriQ-KEM reference implementations, 128/256/384/512
Discovery: Trivial
Exploitation: Secret-seed-dependent execution trace; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`crypto_kem_dec` decrypts with a persistent PKE seed. The decryption path calls `triq_dk_pke_from_string` on every decapsulation, which regenerates the private support using `vect_sample_fixed_weight1`. Its sampler rejects out-of-range or duplicate positions and fetches more XOF bytes when extra draws exhaust a block (`src/ref/vector.c:61-91`). Thus the same public ciphertext can take seed-dependent work. The FO validity selection remains masked, but does not hide this earlier trace. No key-recovery attack is claimed; see `constant_time.md`.

Constant-time fix (moderate, hence Medium): store the expanded support in the private key instead of re-deriving it on every decapsulation, which changes the key format and storage, or sample it with a fixed number of draws and constant-time duplicate handling. Both are well-known techniques with moderate cost.

### Reproducing

```sh
ct_dir=$(mktemp -d)
ref=kem-37/Implementations/Reference_Implementation/TriQ-KEM-128
cc -std=c99 -O3 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I "$ref/src/common" -I "$ref/src/common/triq-128" \
  -I "$ref/src/ref" -I "$ref/src/ref/triq-128" -I "$ref" \
  -o "$ct_dir/repro" kem-37/reproduce_ct_sampler.c \
  "$ref/src/common/symmetric.c" "$ref/auxfunc.c"
"$ct_dir/repro"
```

The witness observes one XOF fetch for seed byte 0 and multiple fetches for seed byte 11 on this build. The full source path is `src/common/kem.c:192` → `src/ref/triq_pke.c:176` → `src/ref/parsing.c:19-22` → `src/ref/vector.c:61-91`.

## kem-37-2: FO re-encryption leaks the decrypted message through sampler timing

Severity: Medium
Status: Lead
Layer: Side-channel
Affected: TriQ-KEM reference and optimized implementations, 128/256/384/512; timing measured on TriQ-KEM-128
Discovery: Moderate
Exploitation: Chosen-ciphertext timing classifier; full key recovery not demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 and Anthropic Claude Opus 5.5 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FJSWIK5YXD6SNYN22H6GT3XE6A5RRKN4/)

Decapsulation decrypts `m_prime`, derives `theta_prime` from it, and re-encrypts before comparing the ciphertext (`src/common/kem.c:192–207`). Re-encryption calls the bounded-density sampler twice (`src/ref/triq_pke.c:113–115`). That sampler exits as soon as a candidate passes its density test, so its iteration count depends on `theta_prime` and hence on the secret-dependent decrypted message (`src/ref/vector.c:244–255`); the optimized trees contain the same early exit. The masked final validity selection does not hide this earlier work. This operational dataflow contradicts the specification's statement that the bounded-density condition is public and independent of secret data (§III-B, p. 9).

The reporters measured a 7.9% probability that a full re-encryption needs at least one extra draw across its two sampler calls, corresponding to about 4.1% per call under the same model. The two timing classes differed by 37,227 cycles: one averaged 10,220,477 cycles and the one-extra-rejection class 10,257,704 cycles (`z` about 4.4); a quieter-host run reached `z=5.6`. A separate microbenchmark measured one extra sampler iteration at roughly 15,674 cycles, so the two figures measure different scopes. This is the re-encryption leakage mechanism used by the published [Don't Reject This attack](https://eprint.iacr.org/2021/1485) on related code-based KEMs. A TriQ-specific classifier is demonstrated, but a complete secret-key recovery is still in progress.

Constant-time fix (moderate, hence Medium): run a fixed, message-independent number of sampler candidates and use masks to select the first acceptable one. The original analysis estimates about 78% extra sampler work for a two-candidate schedule; that performance estimate and its residual failure probability have not been independently validated.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FJSWIK5YXD6SNYN22H6GT3XE6A5RRKN4/) proposes running exactly `N_max` sampler iterations with masked selection, or using another fixed message-independent schedule. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-37/reproduce_reencrypt_sampler.py
```

The compact witness checks the decrypted-message-to-sampler dataflow and early exit in all four archived trees. It deliberately does not claim to reproduce a stable timing classifier or key recovery on every host.
