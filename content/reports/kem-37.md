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

Follow-up analysis: FO re-encryption also samples from coins derived from recovered `m_prime` (`src/common/kem.c:192-200`, `src/ref/triq_pke.c:113-115`). The [Guo et al. HQC/BIKE attack](https://eprint.iacr.org/2021/1485.pdf) suggests a test, not a proven TriQ recovery.

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
