<!-- synchronized report: kem-07/report.md -->
Candidate: BRQC
Family: Code-based (rank metric)
Archive: [BRQC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BRQC.zip) (SHA-256: `2c76bdd4e4df7829bf22fa4949a3c744b9af692425f6f2e5fae5317d41e366ae`)

## kem-07-1: The decoder address trace gives a candidate-specific key-recovery route

Severity: High
Status: Lead
Layer: Side-channel
Affected: Reference implementations, all three parameter sets
Discovery: Non-trivial
Exploitation: Full scaled key recovery from an address-trace oracle; formal-parameter costs are modeled, not executed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; recovery extension by Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-23
Follow-up source: [Sun Shuzhou's PKC Forum post of 2026-10-04](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5ZU7YRLNCOLVVV3RHDBKQFSDETQVTTRY/)

BRQC decryption computes `v-u*y` using private `y` and the public ciphertext (`src/brqc.c:277-288`). The Gabidulin decoder chooses pivot `next` from discrepancies in that word, then uses `next` as the load/store index of `u0` and `u1` (`src/gabidulin.c:185-201`). The address trace is therefore a rank oracle on a secret-key-dependent word. The final KEM ciphertext comparison is masked, but it executes after this leakage.

Further extension to the original analysis: Sun derives secret-support intersection dimensions from chosen ciphertexts and uses them to recover `E_y`; guessing the remaining `x` support then completes the key. The complete chain recovered 3/3 keys on a scaled BRQC instance, with wrong-support, wrong-key, and ciphertext-bit controls. At the submitted dimensions, the modeled adaptive-query costs are about `2^71.4`, `2^86.6`, and `2^119.8`, below the claimed 181-, 295-, and 566-bit classical strengths.

The formal-parameter figures are accounting rather than completed experiments, the complete run changes the field size and dominant index, and no physical cache or wall-clock channel is shown. The stable source-level oracle plus this candidate-specific recovery chain warrants High / Lead. The specification makes an explicit no-leakage claim (physical p. 16), but the side-channel policy reserves Critical for end-to-end recovery at the affected parameters.

Constant-time fix (local-to-moderate; High consequence floor): scan all positions and select `u0[next]` and `u1[next]` with masks. The decoder already computes the pivot and swap masks without branches. The candidate-specific recovery route keeps the classification at High regardless of that remediation cost.

### Reproducing

Inspect `src/kem.c:214`, `src/brqc.c:277-288`, and `src/gabidulin.c:185-201` under `Implementations/Reference_Implementation/BRQC-128/`; the same pivot code is present in BRQC-256/512. See `constant_time.md` for the source trace. The recovery extension has no public reproducer and remains a Lead.

## kem-07-2: Ignored padding bits make ciphertexts malleable without changing the key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: BRQC-128, BRQC-256, and BRQC-512 reference implementations
Discovery: Trivial
Exploitation: One decapsulation query on a byte-distinct copy of the challenge ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §6](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

The `u` and `v` encodings end with 7, 5, or 1 unused bits per vector, which `rbc_vec_from_string` ignores (`rbc_vec.c:789-809`). Decapsulation compares the re-serialized decoded vectors rather than the received bytes (`kem.c:241-252`), and the key hashes those re-serialized vectors (`kem.c:265-266`). Changing any padding bit yields a different ciphertext with the same key. The submission claims IND-CCA2 security, which is trivially violated.

The specification's Algorithm 9 (§3.4) compares the received `(u, v)` with the re-encryption as algebraic values; it defines no byte parser or rule for accepting alternative wire encodings. The submitted byte parser discards the padding bits before the check, so the implementation never compares the original ciphertext bytes.

### Reproducing

```sh
python3 kem-07/reproduce_padding_alias.py
```

## kem-07-3: Secret-key expansion depends on the external DRBG

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: BRQC-128, -256 and -512 reference implementations
Discovery: Trivial
Exploitation: A serialized secret key changes meaning if the external RBG implementation changes; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

BRQC stores a seed and reconstructs its secret supports and polynomials by resetting a local `random_source` from that seed (`parsing.c:56–89`). `random_source_seed_with_len` directly calls the external `init_random_number` (`lib/random_source/random_source.c:27–32`). Correct decapsulation therefore depends on the particular ICCS DRBG stream, although this operation is deterministic key expansion rather than fresh randomness.

The archived implementation is internally consistent. The Low impact is key-format and implementation interoperability; the expansion should use a scheme-defined XOF.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-07-3
```

## kem-07-4: Short ciphertexts reach BRQC's fixed-offset parser

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: BRQC-128, -256 and -512 reference and optimized decapsulation
Discovery: Trivial
Exploitation: A caller-supplied short ciphertext buffer causes an out-of-bounds read; no disclosure or key recovery is demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/BJDASBVXJPRXRQFJCXGSNASJJ32MQ5XI/)

All six `kem_dec` wrappers discard `ct_len_bytes` and pass `ct` to `brqc_decaps`. Its parser reads two fixed-length vectors and the salt at fixed offsets (`src/parsing.c:166–169`), so an actually short buffer is read beyond its allocation. The forum post reports an AddressSanitizer over-read on reference BRQC-128; our certificate checks the same source path in all six trees. Full-length malformed ciphertexts did not crash in the reported tests. No secret disclosure or cryptographic break is demonstrated. The post also points out a negative-degree initialization and an incorrect allocation-result check in the bundled `rbc` library, but establishes no triggering input or memory harm for either; those source-review notes are not classified as separate vulnerabilities here.

### Reproducing

```sh
python3 kem-07/reproduce_short_ciphertext.py
```

This source certificate checks the missing length guard and fixed-offset reads; it does not rerun the forum's sanitizer test.
