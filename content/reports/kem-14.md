<!-- synchronized report: kem-14/report.md -->
Candidate: DTRU
Family: Lattice-based (NTRU)
Archive: [DTRU.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DTRU.zip) (SHA-256: `ed443d6a9e2e6c50e4956e9b30ce078ae0598a8846962d04b9894cac0816527b`)

## kem-14-1: Caller-declared ciphertext length overflows a decapsulation stack buffer

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All seven reference parameter-set source trees; runtime-confirmed in DTRU-Light and DTRU-1024
Discovery: Trivial
Exploitation: In-process memory corruption and process termination; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23
Follow-up source: [DTRU team's confirmation and fix](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4R7ZY3HCMZEPEUVGK2F27X4BYP5Z6AZV/)

The official `kem_dec` API accepts a caller-supplied `ct_len_bytes`, but the reference implementation does not verify it against the instance's fixed ciphertext length. It copies that many bytes into a stack buffer sized for the fixed ciphertext plus `Z` and a short prefix, then writes `Z` at offset `ct_len_bytes`. A correctly allocated, longer input therefore causes an out-of-bounds stack write inside decapsulation. The same unchecked loops appear in all seven reference source trees.

For DTRU-Light, a valid 512-byte ciphertext decapsulates to the honest shared secret; passing those same bytes followed by 48 allocated zero bytes with declared length 560 aborts with stack-smash detection. DTRU-1024 behaves likewise at lengths 1280 and 1360. The effect is memory corruption and availability loss, not a demonstrated confidentiality break. An application that enforces the exact ciphertext length before calling the library can avoid this path, but the submitted API does not enforce that requirement itself.

The DTRU team confirmed the missing validation. Its broader review also found that some optimized paths read the fixed ciphertext size even when the caller supplied a shorter allocation; that is the undersized-input manifestation of the same missing API-length validation.

### Proposed fixes

The [DTRU team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4R7ZY3HCMZEPEUVGK2F27X4BYP5Z6AZV/) proposes exact fixed-ciphertext-length checks before processing or buffer access in every reference, AVX2, resource-optimized, and ARM decapsulation entry point. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kem-14 exploit
```

The witness tests two independent instances, gives the library an input allocation matching the declared length, checks normal decapsulation first, and isolates each crash in a subprocess. It prints `ATTACK kem-14-1 ... CONFIRMED` for both.

## kem-14-2: Decapsulation return value exposes the implicit-rejection branch

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All seven reference parameter sets; the DTRU team reports fixing the wider implementation set
Discovery: Trivial
Exploitation: Ciphertext-validity oracle through the public return value; no standalone IND-CCA break demonstrated
Credit: 赵运磊 (on behalf of the DTRU team)
Date: 2026-09-27
Original source: [DTRU team's PKC Forum disclosure and fix](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4R7ZY3HCMZEPEUVGK2F27X4BYP5Z6AZV/)

The specified FO transform uses implicit rejection: an invalid ciphertext yields a pseudorandom rejection key without revealing which branch was selected. Every reference `kem_dec` instead ends with `return fail;`, returning `0` after successful re-encryption and `1` after failure even though the shared-secret buffer is selected in constant time. Thus a correctly sized modified ciphertext exposes its validity directly through the API.

This signal alone is not a demonstrated IND-CCA break: explicit-rejection FO variants can be secure, and the contest API has an error return. The finding is the implementation's violation of DTRU's specified implicit-rejection contract. The DTRU team confirmed the discrepancy.

### Proposed fixes

The [DTRU team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4R7ZY3HCMZEPEUVGK2F27X4BYP5Z6AZV/) proposes retaining constant-time key selection, returning `0` on every correctly sized decapsulation, and reserving negative returns for public-API input errors. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kem-14 exploit-rejection-contract
```

The witness first checks an honest encapsulation, then changes one ciphertext byte and requires the submitted decapsulator to return `1` while producing a deterministic rejection key. It also source-checks the same `return fail;` path in all seven reference trees and prints `ATTACK kem-14-2 ... CONFIRMED`.

## kem-14-3: Rejection key omits the specified public-key binding

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All seven reference parameter sets
Discovery: Trivial
Exploitation: Correlated keys with different public keys and equal rejection seeds alias on every rejected ciphertext; no honest-key IND-CCA break demonstrated
Credit: 赵运磊 (on behalf of the DTRU team)
Date: 2026-09-27
Original source: [DTRU team's PKC Forum disclosure](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4R7ZY3HCMZEPEUVGK2F27X4BYP5Z6AZV/)

The specification derives the rejection key as `H1(ID(pk), z, c)`. All seven reference implementations instead compute `pseudohash(512, c || z)`: `ID(pk)` is absent, the operands are reversed, and the ordinary hash is reused without the specified domain separation. Consequently, distinct keys containing the same rejection seed return the same rejection key for a common invalid ciphertext, even when their public keys differ.

The submitted generator samples `z` independently, so this correlated-key witness is not an attack on honestly and independently generated keys and does not establish an IND-CCA break. It demonstrates precisely the missing multi-key binding that the specified `ID(pk)` input is intended to provide. The DTRU team independently identified the omission.

### Proposed fixes

The [DTRU team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4R7ZY3HCMZEPEUVGK2F27X4BYP5Z6AZV/) announces an updated implementation after noting that the code omits the specification's `ID(pk)` input. This section records the proposal without inferring implementation details or evaluating it.

### Reproducing

```sh
make -C kem-14 exploit-rejection-contract
```

The witness generates two different keys, copies only the first key's 32-byte rejection seed into the second secret key, and decapsulates one invalid ciphertext under both. The rejection keys become identical; retaining the second key's original seed is a negative control and produces a different value. It prints `ATTACK kem-14-3 ... CONFIRMED`.

## kem-14-4: Ring-paired DoubleE8 blocks invalidate DTRU's failure estimates

Severity: Medium
Status: Proof gap
Layer: Design
Affected: DTRU-648, DTRU-768, DTRU-1024, conditionally DTRU-Prime, DTRU-1536 and DTRU-2048; DTRU-Light is a control
Discovery: Hard
Exploitation: Covariance-aware failure estimates undermine the submitted proof, but no full-size failure search or key recovery was executed
Credit: Yuyang Xiao, Institute of Software, Chinese Academy of Sciences <xiaoyuyang2023@iscas.ac.cn>
Date: 2026-09-28
Reference: [Xiao, ePrint 2026/2250](https://eprint.iacr.org/archive/2026/2250/1790598276.pdf)

DoubleE8 places each E8 octet beside its `n/2`-shifted copy (§1.1, physical p. 2). Multiplication in `Z[x]/(x^n-x^(n/2)+1)` couples exactly those coordinates, whereas the submitted DFR analysis treats the 16 decoder inputs as independent (Theorem 1 and §2.3, physical pp. 8–9). Xiao's covariance-aware model gives block eigenvalues around 0.3 and 1.6–2.1 times the marginal variance. Its uncapped first-failure estimates are about `2^85.4`, `2^97.9`, `2^104.6`, `2^96.3`, `2^100.7` and `2^110.8` in the Affected order above, 50–110 bits below the submitted DFR exponents. At the call's `2^80` decapsulation ceiling, Table 5 gives total costs of `2^83.7`, `2^86.0`, `2^98.9`, `2^79.8`, `2^94.5` and `2^116.1`. DTRU-Light's power-of-two ring does not have this pairing. For odd-dimensional DTRU-Prime, the specification does not state the DoubleE8 layout; its listed result is conditional on Xiao's assumed offset `floor(n/2)=543`.

A failing honest encapsulation is recognizable from its known shared key. The paper develops directional follow-ups and a toy secret-correlation experiment, but no full-size recovery. Its normal-tail fits use 200 ciphertexts, the extreme tails are extrapolated, and the Prime result assumes a layout absent from the specification. The result therefore establishes a substantive failure-proof gap rather than a completed attack.

Further extension to Xiao's analysis: direct public multiplication-matrix calculations on all five tricyclotomic dimensions give paired correlations around `-0.65` and normalized 16-row covariance eigenvalues from about 0.27 to 2.12. This independently certifies structural non-independence, not the extreme-tail DFR estimates. Even the submission's own DFR values leave Theorem 3's `(qH+qD) delta` term far above every target when `qD=2^80` (physical p. 12).

### Reproducing

```sh
python3 kem-14/reproduce_dtru_covariance.py
```

The dependency-free certificate constructs the multiplication rows, checks their paired correlations and spectrum, and evaluates the submitted DFR exponents at `2^80` queries. It does not reproduce the paper's tail fitting or a key-recovery attack.
