<!-- synchronized report: kem-07/report.md -->
Candidate: BRQC
Family: Code-based (rank metric)
Archive: [BRQC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BRQC.zip) (SHA-256: `2c76bdd4e4df7829bf22fa4949a3c744b9af692425f6f2e5fae5317d41e366ae`)

## kem-07-1: Secret-derived decoder pivots select memory addresses

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all three parameter sets
Discovery: Moderate
Exploitation: Local cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

BRQC decryption computes `v-u*y` using private `y` and the public ciphertext (`src/brqc.c:277-288`). The Gabidulin decoder chooses pivot `next` from discrepancies in that word, then uses `next` as the load/store index of `u0` and `u1` (`src/gabidulin.c:185-201`). Those addresses vary with a secret-key-derived intermediate. The final KEM ciphertext comparison is masked, but it executes after this leakage. No complete key recovery or remote timing channel is demonstrated.

Constant-time fix (easy, hence Low): the decoder already follows the constant-time Gabidulin decoding of Bettaieb, Bidoux, Gaborit and Marcatel, PQCrypto 2019: the pivot `next` is computed with masks and the swap is masked. Only the accesses to `u0[next]` and `u1[next]` use the secret index. A masked swap over all n positions removes them; it adds at most n field-element copies per iteration, O(n^2) in total, which is below the decoder's existing q-polynomial work. The specification states that the provided implementations run in constant time (physical PDF page 16), which this access contradicts.

### Reproducing

Inspect `src/kem.c:214`, `src/brqc.c:277-288`, and `src/gabidulin.c:185-201` under `Implementations/Reference_Implementation/BRQC-128/`; the same pivot code is present in BRQC-256/512. See `constant_time.md` for the fuller trace.

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
