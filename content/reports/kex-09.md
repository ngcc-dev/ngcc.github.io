<!-- synchronized report: kex-09/report.md -->
Candidate: TriQ-KEX
Family: Code-based authenticated key exchange
Archive: [TriQ-KEX.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TriQ-KEX.zip)

## kex-09-1: Decapsulation re-expands its secret key with a variable-length sampler

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: TriQ-KEX reference implementations (128, 256, 384, 512)
Discovery: Trivial
Exploitation: Secret-seed-dependent control flow and work on each decapsulation; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`crypto_kem_dec()` passes the persistent secret PKE seed to `triq_pke_decrypt()`, which calls `triq_dk_pke_from_string()` on every decapsulation. That function expands the seed through `vect_sample_fixed_weight1()`. Its support sampler repeats on rejected or duplicate secret-derived positions (`vector.c:69-90`), and refills an XOF buffer when the extra draws cross its boundary. Thus otherwise identical decapsulation calls perform a secret-key-dependent number of loop iterations and XOF calls. The four reference variants share the same sampler. This is a secret-dependent timing/control-flow leak, not an established full-key attack; see `constant_time.md` for the data-flow trace.

### Reproducing

From the repository root, compile the witness against the submitted TriQ-128 source:

```sh
ct_dir=$(mktemp -d)
ref=kex-09/TriQ-KEX/Implementations/Reference_Implementation/TriQ-KEX-128
cc -std=c99 -O3 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I "$ref/src/common" -I "$ref/src/common/triq-128" \
  -I "$ref/src/ref" -I "$ref/src/ref/triq-128" -I "$ref" \
  -o "$ct_dir/repro" kex-09/reproduce_ct_sampler.c \
  "$ref/src/common/symmetric.c" "$ref/auxfunc.c"
"$ct_dir/repro"
```

The witness counts XOF fetch calls in the unmodified reference sampler. It prints `CONFIRMED` after finding two secret seeds (first byte 0 and 11 in this build) that require different call counts. An extra fetch performs another XOF invocation and allocation, making the paths observably different without a statistical timing test.

Follow-up analysis: decapsulation re-encryption also runs a bounded-density sampler on coins derived from recovered `m_prime` (`src/common/kem.c:156-164`, `src/ref/triq_pke.c:96-98`). This is a [Guo et al.](https://eprint.iacr.org/2021/1485.pdf)-style lead; no TriQ-specific key-recovery oracle is yet demonstrated.
