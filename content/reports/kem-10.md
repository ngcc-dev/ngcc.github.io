<!-- synchronized report: kem-10/report.md -->
Candidate: C-Multi-UR-AG
Family: Code-based (rank metric)
Archive: [C-Multi-UR-AG.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/C-Multi-UR-AG.zip) (SHA-256: `c41e372a55e1dd4aa0e30c6b53d9d7b4f9cd1d7ae431763535e1e61097445e2c`)

## kem-10-1: Malformed ciphertexts crash the reference decapsulator

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All three reference parameter sets
Discovery: Trivial
Exploitation: Unauthenticated decapsulation request causes process termination; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The shipped C-Multi-UR-AG decapsulator does not safely reject malformed ciphertexts. With an honestly generated key, an all-zero ciphertext triggers stack-smash detection in CMultiURAG-128 and a segmentation fault in CMultiURAG-512. A sampled single-bit change to an honest ciphertext segfaults in CMultiURAG-256. All three unmodified reference libraries pass their honest KATs. These are attacker-controlled, fixed-length ciphertexts, not truncated buffers or corrupted secret keys.

For the 128-bit instance, a debugger places the stack-smash in `rbc_elt_mul`, called from `rbc_qpoly_mul2` through `rbc_qpoly_left_div2` and the augmented-Gabidulin decoder. In `src/qpoly.c`, `rbc_qpoly_left_div2` decrements its signed iteration bound without checking exhaustion and passes that value as an unsigned degree to `rbc_qpoly_mul2`, whose loop uses it to index polynomial coefficients. This is a concrete unsafe decoder path; the observed effect is process termination. No secret disclosure, shared-secret recovery, or arbitrary-code execution is established.

Decapsulation must validate decoder bounds and return a defined rejection result on malformed ciphertexts. Merely replacing a process crash with the same unchecked polynomial access is insufficient.

### Reproducing

```sh
make -C security
make -C kem-10 libs
security/ngcc_security kem-10/lib/libCMultiURAG-128.so kem-zero
security/ngcc_security kem-10/lib/libCMultiURAG-256.so kem-ciphertext-flip
security/ngcc_security kem-10/lib/libCMultiURAG-512.so kem-zero
```

Each command runs in its own process because the attack input terminates that process. The 128-bit and 512-bit zero-ciphertext cases, and the 256-bit mutation, reproduced locally; `make -C kem-10 test` passed all three honest-input KAT sets.

## kem-10-2: Secret-derived decoder pivots select memory addresses

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all three parameter sets
Discovery: Moderate
Exploitation: Local cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

C-Multi-UR-AG decryption computes a rank-code word using the private matrix `Y` and the public ciphertext (`src/cmultiurag.c:248-257`). The augmented-Gabidulin decoder derives pivot `next` from discrepancies in that word and uses it directly to load and store `u0` and `u1` (`src/augmented_gabidulin.c:185-201`). This exposes a secret-key-dependent memory-access pattern even though final KEM fallback selection is masked. No complete key recovery or remote timing channel is demonstrated.

### Reproducing

Inspect `src/kem.c:209-213`, `src/cmultiurag.c:248-257`, and `src/augmented_gabidulin.c:185-201` under `Implementations/Reference_Implementation/CMultiURAG-128/`; the same pivot code is present in the other reference sets. See `constant_time.md` for the fuller trace.

## kem-10-3: Ignored padding bits make CMultiURAG-512 ciphertexts malleable without changing the key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CMultiURAG-512 reference implementation; the 128 and 256 encodings have no padding
Discovery: Trivial
Exploitation: One decapsulation query on a byte-distinct copy of the challenge ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

With `m = 181`, the `U` and `V` encodings each end with 5 unused bits, which `rbc_vec_from_string` ignores (`rbc_vec.c:789-809`). Decapsulation compares the re-serialized decoded `U, V` with the re-encryption (`kem.c:235-246`), and the key hashes the re-serialized values (`kem.c:257-262`). Each honest ciphertext has 1,023 byte-distinct variants with the same key. The submission claims IND-CCA2 security, which is trivially violated.

### Reproducing

```sh
python3 kem-10/reproduce_padding_alias.py
```
