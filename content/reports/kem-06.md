<!-- synchronized report: kem-06/report.md -->
Candidate: BRA
Family: Code-based (rank metric)
Archive: [BRA.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BRA.zip) (SHA-256: `612a3fe69c7a28fae7ca87a226d29e67a9cffb6ce9e4cbe54ac9de37f7650d7a`)

## kem-06-1: A malformed secret key drives the BRA decoder out of bounds

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: BRA-128 reference implementation; the same unchecked routine is present in BRA-256 and BRA-512
Discovery: Moderate
Exploitation: One-byte secret-key corruption followed by decapsulation; remote control of the secret key is not established
Credit: Dariia Porechna ([@dariolina](https://github.com/dariolina))
Date: 2026-09-22
Original source: [ngcc-dev/ngcc-harness PR #6](https://github.com/ngcc-dev/ngcc-harness/pull/6)

After an honest BRA-128 key generation, encapsulation, and decapsulation, changing secret-key byte 0 and decapsulating the otherwise honest ciphertext reaches an unchecked bound in the augmented-Gabidulin decoder. `rbc_qpoly_left_div2` initializes a signed counter to `k-1`, decrements it once per division iteration without checking for exhaustion, and passes it as the unsigned `p2_degree` argument to `rbc_qpoly_mul2`. The latter checks the polynomials' stored degrees, not the explicit iteration bounds it actually uses.

AddressSanitizer consequently reports a heap-buffer-overflow when `rbc_qpoly_mul2` first reads `p2->values[j]` past the four-coefficient allocation at `qpoly.c:458`; its following output access at line 460 would likewise become out of bounds if execution continued. The same defective control flow exists in all three submitted parameter-set sources, although the deterministic runtime witness below confirms BRA-128 only.

The standard KEM threat model gives a remote peer the ciphertext, not the recipient's secret key. This witness therefore does not establish a remote chosen-ciphertext attack, key recovery, or loss of confidentiality. It does establish unsafe handling of a corrupted, faulted, imported, or maliciously provisioned secret key, with process termination and memory corruption as possible consequences. The decoder should reject an exhausted/negative division bound and validate the explicit multiplication degrees against both input and output allocations.

### Reproducing

```sh
make -C kem-06 exploit
```

The target first completes the honest round trip, then repeats decapsulation after changing only secret-key byte 0 and requires ASan to identify the unchecked q-polynomial access. Its narrow sanitizer ignore-list excludes a separate pre-decoder stack-redzone access in the submitted field multiplier so that the decoder witness can be reached; no decoder code is modified.

## kem-06-2: Reference field multiplication touches one limb past its output

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: BRA-128 and BRA-256 reference implementations
Discovery: Trivial
Exploitation: Every field multiplication performs an out-of-bounds read-modify-write; no remote nonzero overwrite is demonstrated
Credit: Further extension to Dariia Porechna's analysis
Date: 2026-09-22
Original source: [ngcc-dev/ngcc-harness PR #6](https://github.com/ngcc-dev/ngcc-harness/pull/6)

Further extension to Dariia Porechna's analysis: the reference `rbc_elt_ur_mul` loop iterates `j` through `ELT_SIZE` inclusive and writes `o[j+offset]`. For the 67- and 83-bit fields, `ELT_SIZE` is 2, `offset` becomes 1, but `rbc_elt_ur` contains only three limbs. The `j = 2` iteration therefore reads and writes limb 3, one limb past the declared output. This is a real C out-of-bounds access rather than an ASan layout artifact: placing an exact-size output at a guard-page boundary makes the submitted function fault for both fields.

The access occurs in normal operation. `rbc_elt_mul` allocates an exact-size `rbc_elt_ur` on its stack and calls this routine; the polynomial multiplication used by honest key generation, encapsulation, and decapsulation calls `rbc_elt_mul`. A full ASan build stops during honest BRA-128 key generation at this access. The guard-page witness also provides two useful controls: multiplication returns when the following page is writable, and the 127-bit BRA-512 reference routine stays within its four-limb output when the following page is inaccessible. The optimized BRA-128 and BRA-256 sources likewise allocate four limbs and do not have this exact bound mismatch.

For canonical 67- and 83-bit operands, the fourth-limb contribution is mathematically zero, so ordinary layouts usually rewrite the adjacent word without changing its value. This limits the demonstrated impact to undefined behavior and possible faults on a hard allocation boundary; the audit has not shown attacker-controlled nonzero corruption, key recovery, or a remote KEM break. The reference loop should stop when `j + offset == ELT_UR_SIZE`, or the output representation should explicitly include the padding limb.

### Reproducing

```sh
make -C kem-06 exploit-field
```

The ordinary, unsanitized guard-page test confirms faults for GF(2^67) and GF(2^83), then confirms GF(2^127) as an in-bounds negative control.

## kem-06-3: Secret-derived decoder pivots select memory addresses

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all three parameter sets
Discovery: Moderate
Exploitation: Local cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

BRA decryption computes `v-u*y` using private `y` and the public ciphertext (`src/bra.c:277-288`). The augmented-Gabidulin decoder derives pivot `next` from discrepancies in that word and uses `next` directly to load and store `u0` and `u1` (`src/augmented_gabidulin.c:184-205`). A cache observer can therefore learn a secret-key-dependent intermediate. The final KEM ciphertext comparison and fallback selection are masked, but occur after the decoder. No complete key recovery or remote timing channel is demonstrated.

### Reproducing

Inspect `src/kem.c:214`, `src/bra.c:277-288`, and `src/augmented_gabidulin.c:184-205` under `Implementations/Reference_Implementation/BRA-128/`; the same pivot code is present in BRA-256/512. See `constant_time.md` for the fuller trace.

## kem-06-4: Ignored padding bits make ciphertexts malleable without changing the key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: BRA-128, BRA-256, and BRA-512 reference implementations
Discovery: Trivial
Exploitation: One decapsulation query on a byte-distinct copy of the challenge ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

The `u` and `v` encodings end with 5 unused bits each, which `rbc_vec_from_string` ignores (`rbc_vec.c:789-809`). Decapsulation compares the re-serialized decoded vectors rather than the received bytes (`kem.c:241-252`), and the key hashes those re-serialized vectors (`kem.c:265-266`). Every honest ciphertext therefore has 1,023 byte-distinct variants that decapsulate to the same key. The submission claims IND-CCA2 security, which is trivially violated.

The specification's Algorithm 9 (§3.4) compares the received `(u, v)` with the re-encryption as algebraic values; it defines no byte parser or rule for accepting alternative wire encodings. The submitted byte parser discards the padding bits before the check, so the implementation never compares the original ciphertext bytes.

### Reproducing

```sh
python3 kem-06/reproduce_padding_alias.py
```
