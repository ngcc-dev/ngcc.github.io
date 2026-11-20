<!-- synchronized report: kem-11/report.md -->
Candidate: COMPASS-KEM
Family: Lattice-based
Archive: [COMPASS-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/COMPASS-KEM.zip) (SHA-256: `8fc838488ac0849d4c6afd161f8b9742c7a8b9a330bc3b79df70ced7e2d1d5e2`)

## kem-11-1: COMPASS-KEM-384 and -512 use a 256-bit key-generation root

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: COMPASS-KEM-384 and COMPASS-KEM-512 reference implementations and specification
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The COMPASS-KEM algorithms define both the initial key-generation seed and the shared key as `n`-bit values. The submitted COMPASS-KEM-384 and COMPASS-KEM-512 implementations instead fix `SYMBYTES` and `SSBYTES` at 32 bytes.

The entire IND-CPA key pair is a deterministic function of one 256-bit `coins` value. There are therefore at most `2^256` generated public keys: enumerate the root, regenerate the public key, and compare it with the target to recover the corresponding secret key. The KEM output independently has at most 256 bits of delivered-key capacity.

This caps both implementations at 256 bits despite their respective 384- and 512-bit classical claims. The specification is internally inconsistent: Algorithm 1 requests an `n`-bit seed, while its implementation notes on physical PDF page 25 say that one could store only a “32-byte core seed” and rerun key generation. The submitted code follows the shorter interpretation.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-11-1
```

The check verifies the source constants and deterministic expansion against physical PDF pages 9, 12, 16, and 25.

## kem-11-2: The Biased-MLWR reduction does not instantiate the concrete small-secret sets

Severity: Medium
Status: Proof gap
Layer: Design
Affected: All four COMPASS-KEM parameter sets
Discovery: Moderate
Exploitation: Proof gap; no distinguishing or key-recovery attack demonstrated
Credit: Make
Date: 2026-10-02
Original source: [Make's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VQEI56DFEV7TIEGRXDN6O4P2T6DZ66DE/)

COMPASS-KEM's IND-CPA proof states Theorem 2 on physical p. 20 and uses Biased MLWR for its Game 2-to-Game 3 transition on p. 21. Definition 2 instead defines that problem with a uniform secret, and Theorem 1 relies on a uniformly random bounded component satisfying its leftover-hash-lemma inequality (physical pp. 16–17). Concrete encryption samples `r` from `CBD_eta` with `eta` in `{2,3,4}` (Algorithm 2, physical p. 14; Table 1, p. 18; `indcpa.c:336–337`). The submission gives no reduction from these concrete distributions to the stated assumption.

Further extension to Make's analysis: even granting each concrete coefficient the greater entropy of a uniform draw over its full `2 eta + 1` support leaves the displayed inequality short by 6,307, 7,121, 14,629 and 14,357 bits at the 128-, 256-, 384- and 512-bit sets. This quantifies a missing proof bridge, not an attack; the heuristic lattice estimates are separate.

### Reproducing

```sh
python3 kem-11/reproduce_biased_mlwr_gap.py
```

The certificate extracts the theorem's condition, checks each implementation's parameters and CBD call, and evaluates the optimistic entropy bound.

## kem-11-3: A failed hash allocation leaves the previous session key in encapsulation

Severity: High
Status: Confirmed
Layer: Implementation
Affected: COMPASS-KEM-128, -256, -384 and -512, reference and optimized implementations
Discovery: Moderate
Exploitation: If one hash allocation fails, encapsulation returns success with the previous call's shared secret, which an earlier recipient already holds; no remote way to force the failure is shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; stale-key consequence and witness by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-20
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QJQS6ALEKKNICEISNLNUZS265O4Y523T/)

`crypto_kem_enc_derand` keeps the key and coins in an uninitialised stack array `kr` (`kem.c:85` in the reference trees, `:84` in the optimized) and fills it with `hash_g` (`:91`), a macro for the contest's `pseudohash` whose status is not checked (`symmetric.h:42–43`). When the helper's first allocation fails (`auxfunc.c:229`) it returns without writing `kr`. Encapsulation then encrypts with the coins in `kr` (`kem.c:94`), copies its first half into the shared secret (`:96`), and returns 0.

In the witness one process encapsulates to Mallory and then to Bob with that allocation failing. The stale `kr` is the previous call's, so the key returned for Bob equals the key Mallory decapsulated, in all eight builds. Without the fault, and when the stack is overwritten between the two calls, Mallory's key does not match. The reused value depends on the call sequence and on the compiler's stack layout.

The post lists the unchecked statuses of `pseudoXOF`, `sm3hash` and `pseudohash` as a maintenance detail; it does not report this consequence. The failing allocation is a fixed-size buffer inside the contest helper. KEM input sizes are fixed, so a caller cannot choose it, and no remote way to force the failure is shown; memory pressure or a resource limit is needed. The candidate's defect is discarding the helper's status and returning success. A demonstrated session-key exposure under these preconditions is High.

### Reproducing

```sh
sh kem-11/reproduce_stale_encaps_key.sh
```

The witness wraps `malloc` to fail the 66-byte allocation of `hash_g` in the second encapsulation and requires Mallory to predict the Alice–Bob key in that run only.

## kem-11-4: The KEM API ignores declared input lengths and over-reads short buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: COMPASS-KEM-128, -256, -384 and -512, reference and optimized implementations; the sampler over-read affects optimized COMPASS-KEM-128 and -384 only
Discovery: Trivial
Exploitation: Out-of-bounds read from a caller-supplied short ciphertext or public key; no disclosure shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; sampler over-read by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-20
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QJQS6ALEKKNICEISNLNUZS265O4Y523T/)

`kem_enc` and `kem_dec` discard `pk_len_bytes`, `sk_len_bytes` and `ct_len_bytes` (`KEM_AlgorithmInstance.c:52,63–64` in the reference trees, `:49,60–61` in the optimized), and the functions they call read their inputs at compile-time sizes. Under AddressSanitizer, an honest ciphertext in a heap buffer of exactly 16 bytes, or one byte short, gave a heap-buffer-overflow read in `poly_decompress` during decapsulation, and a public key one byte short gave one during encapsulation, in all eight trees. Full-length inputs ran cleanly and decapsulated to the encapsulated key. Callers that pass complete inputs are unaffected.

The optimized η1 = 3 sampler `poly_cbd3_avx` loads 16 bytes for every 12 it consumes (`cbd.c:189`), and the noise buffers in `polyvec_getnoise_eta1_avx` hold exactly `ETA1*N/4` bytes (`indcpa.c:23`). Its last load therefore reads 4 bytes past a stack buffer on honest key generation at COMPASS-KEM-128 and -384. The shuffle discards those bytes, so outputs are unaffected.

### Reproducing

```sh
sh kem-11/reproduce_short_inputs.sh
```

The optimized AddressSanitizer builds use `-mavx2 -mbmi2 -mpopcnt` without the Makefile's `-march=native`.
