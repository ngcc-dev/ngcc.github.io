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

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §17](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

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

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all three parameter sets
Discovery: Moderate
Exploitation: Local cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

C-Multi-UR-AG decryption computes a rank-code word using the private matrix `Y` and the public ciphertext (`src/cmultiurag.c:248-257`). The augmented-Gabidulin decoder derives pivot `next` from discrepancies in that word and uses it directly to load and store `u0` and `u1` (`src/augmented_gabidulin.c:185-201`). This exposes a secret-key-dependent memory-access pattern even though final KEM fallback selection is masked. No complete key recovery or remote timing channel is demonstrated.

Constant-time fix (easy, hence Low): the decoder already follows the constant-time Gabidulin decoding of Bettaieb, Bidoux, Gaborit and Marcatel, PQCrypto 2019: the pivot `next` is computed with masks and the swap is masked. Only the accesses to `u0[next]` and `u1[next]` use the secret index. A masked swap over all n positions removes them; it adds at most n field-element copies per iteration, O(n^2) in total, which is below the decoder's existing q-polynomial work. The specification states that the provided implementations run in constant time (physical PDF page 15), which this access contradicts.

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

The specification's Algorithm 9 (§3.4) compares the received `(U, V)` with the re-encryption as algebraic values; it defines no byte parser or rule for accepting alternative wire encodings. The submitted byte parser discards the padding bits before the check, so the implementation never compares the original ciphertext bytes.

### Reproducing

```sh
python3 kem-10/reproduce_padding_alias.py
```

## kem-10-4: Secret-key expansion depends on the external DRBG

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: CMultiURAG-128, -256 and -512 reference implementations
Discovery: Trivial
Exploitation: A serialized secret key changes meaning if the external RBG implementation changes; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

C-Multi-UR-AG stores a seed and reconstructs secret supports and matrices by resetting a local `random_source` (`parsing.c:50–71`). Its seed operation directly calls the external `init_random_number` (`lib/random_source/random_source.c:27–32`). Correct decapsulation therefore makes the particular ICCS DRBG stream part of the serialized secret-key format.

The bundled implementation works consistently. The Low impact is key-format and implementation interoperability; deterministic expansion should use a scheme-defined XOF.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-10-4
```

## kem-10-5: Short ciphertexts reach the fixed-offset parser

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: CMultiURAG-128, -256 and -512 reference and optimized decapsulation
Discovery: Trivial
Exploitation: A caller-supplied short ciphertext buffer causes an out-of-bounds read; no disclosure or key recovery is demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GDMB53GE3SVJ3V2R6O53GBWLWIXBAWYE/)

All six `kem_dec` wrappers discard `ct_len_bytes` and pass `ct` to `cmultiurag_decaps`. Its parser reads both matrices and the salt at fixed offsets (`src/parsing.c:145–148`), so a genuinely short allocation is read beyond its end. The forum reports an AddressSanitizer over-read on reference CMultiURAG-128; our certificate checks the six source paths. No memory disclosure or cryptographic break is shown.

### Reproducing

```sh
python3 kem-10/reproduce_implementation_findings.py --report-id kem-10-5
```

The certificate checks source, not the forum's sanitizer run.

## kem-10-6: Reference 79-bit field multiplication touches a fourth limb

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference CMultiURAG-128
Discovery: Trivial
Exploitation: An out-of-bounds read-modify-write occurs on honest field multiplication; no attacker-controlled nonzero overwrite is demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/GDMB53GE3SVJ3V2R6O53GBWLWIXBAWYE/)

The reference 79-bit field declares `rbc_elt_ur` with three limbs (`src/rbc-79/rbc_79.h:18,33`). In `rbc_elt_ur_mul`, the inner loop includes `j = RBC_79_ELT_SIZE = 2`; for outer-loop `i ≥ 64`, `offset = 1`, so `o[j+offset]` accesses limb 3 (`rbc_elt.c:428–435`). The forum reports an AddressSanitizer failure during honest key generation. For reduced operands the value XORed at that location is zero, so the evidence shows undefined behavior and sanitizer failure, not useful memory corruption. The 256/512 reference fields and optimized multiplication use different bounds or code.

### Reproducing

```sh
python3 kem-10/reproduce_implementation_findings.py --report-id kem-10-6
```

The certificate checks the offending loop and dimensions; it does not rerun the sanitizer test.
