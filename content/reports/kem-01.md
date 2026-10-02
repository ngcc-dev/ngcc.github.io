<!-- synchronized report: kem-01/report.md -->
Candidate: Aigis-Enc+
Family: Lattice (Module-LWE)
Archive: [Aigis-Enc+.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Aigis-Enc%2B.zip) (SHA-256: `1c053133175cd189fd9f0e058bde684168f55a6fc3871de2a755404a08990186`)

## kem-01-1: Ineffective implicit rejection breaks IND-CCA security

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §7](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

Changing a ciphertext bit frequently leaves the decapsulated shared secret unchanged. An exhaustive sweep of Aigis-enc1 found that 5,632 of 7,168 single-bit ciphertext changes return the original shared secret. The same defect was reproduced in the other two parameter sets.

`mkem_dec` writes the candidate valid secret to the output before checking the re-encrypted ciphertext. On failure, the intended constant-time replacement writes into the wrong buffer, leaving the already-returned candidate secret untouched. Rejection is therefore ineffective.

An attacker given a challenge ciphertext and candidate challenge key can modify the ciphertext, decapsulate it through the allowed CCA oracle, and compare the result with the candidate key. Retention identifies the real encapsulated key and provides a direct IND-CCA distinguisher. This violates the claimed IND-CCA security at every submitted level.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-01
tools/ngcc_attack kem-ct-flip kem-01/lib/libAigis-enc1.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

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
