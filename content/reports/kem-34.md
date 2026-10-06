<!-- synchronized report: kem-34/report.md -->
Candidate: Rudraksh2
Family: Lattice-based KEM
Archive: [Rudraksh2.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Rudraksh2.zip) (SHA-256: `569d526cf7abe38393f69a4513686fa86a0c3b3033cc225b84cc107b20b17b98`)

## kem-34-1: Rudraksh2-128 leaves only a 2^64-query Grover margin

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Rudraksh2-128-I; the same 128-bit message dimension is specified for Rudraksh2-128-II
Discovery: Trivial
Exploitation: About 2^64 Grover oracle iterations; total quantum circuit cost is not established below 2^80
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

Rudraksh2-128 samples a 16-byte encapsulation message `m`, then derives both the session key and the public encryption randomness as `G(m || H(pk))` (`params.h:41–50`, `KEM_lwekem128.c:73–97`). Given a ciphertext and public key, a candidate message is publicly testable by recomputing the encryption. Generic Grover search therefore needs about `2^64` such oracle iterations. This is below the set's nominal 80-bit quantum exponent if one counts oracle calls alone, but each oracle must implement and uncompute the full public encryption test. The NGCC call does not specify the quantum cost metric precisely, and no gate-level estimate establishes total work below `2^80`; this is therefore a parameter-analysis gap rather than a confirmed claim break. The observation remains after replacing the contest placeholder XOF with an ideal primitive of the same dimensions.

The witness resets the deterministic test generator to recover the encapsulator's `m`, then reconstructs all 32 session keys as `G(m || H(pk))` without using the secret key or ciphertext. It demonstrates the public reduction but does not run the generic `2^64` search.

### Reproducing

```sh
make -C kem-34 reproduce-message-space
python3 kem-34/reproduce_parameters.py
```

## kem-34-2: Cortex-M4 uses an incompatible Minal decoder constant

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rudraksh2-128 and -256 Cortex-M4 implementations
Discovery: Trivial
Exploitation: Honest cross-implementation sessions derive different keys
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

The Cortex-M4 128- and 256-bit trees set `MINAL_BETA` to 0 (`minal.c:15`), whereas the specification, reference, and optimized implementations use 220. This constant changes the two-dimensional error-correcting code. Cross-tests reproduced zero matching keys in 200 sessions in each direction between Cortex-M4 and reference code; Cortex-M4 self-tests succeeded, and changing only the constant to 220 restored 200/200 interoperability in both directions. This is an availability/interoperability defect, not a confidentiality break.

### Proposed fixes

The original post proposes changing `MINAL_BETA` to 220 in the Cortex-M4 128- and 256-bit implementations.

### Reproducing

```sh
python3 kem-34/reproduce_parameters.py
```

The compact witness verifies the conflicting constants in the archived trees. The original package contains the full cross-implementation experiment.

## kem-34-3: KEM entry points ignore caller-declared buffer lengths

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Rudraksh2 reference implementations
Discovery: Trivial
Exploitation: Out-of-bounds read from a caller-supplied short buffer
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

`kem_enc` and `kem_dec` accept public-key and ciphertext lengths but never inspect them, and `kem_dec` likewise ignores the supplied secret-key length. They instead read the compile-time sizes (`KEM_lwekem128.c:73–99,102–144`). Passing `kem_dec` an allocation one byte shorter than the normal 912-byte ciphertext and its true length of 911 produces an AddressSanitizer heap-buffer-overflow read at `poly.c:105`, reached through `indcpa.c:121`. No disclosure, write, or control-flow impact is demonstrated.

### Proposed fixes

The original post proposes validating caller-supplied lengths before accessing the public key or ciphertext.

### Reproducing

```sh
make -C kem-34 reproduce-length-read
```

## kem-34-4: Rudraksh2-II's modulus cannot support its specified NTT

Severity: Info
Status: Confirmed
Layer: Design
Affected: Rudraksh2-128-II, -256-II, and -512-II specifications
Discovery: Trivial
Exploitation: The specified NTT cannot be realized for these parameters; no security consequence is shown
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3QHUJGWZDN7ZFSG7R46HHEWG67MKGYYB/)

The specification requires a primitive `2n`-th root of unity in `Z_q` for its negacyclic NTT. Every `-II` set uses `q=4001`, but `q-1 = 4000 = 2^5 * 5^3`; the largest supported negacyclic-NTT degree is therefore 16. The specified degrees are 64, 128, and 256, so none has the required root. The submission supplies no `-II` implementation. The polynomial ring itself remains implementable by a different multiplication method. This is a realization note, not a security vulnerability: no submitted `-II` implementation fails, and no attack or availability failure is shown.

### Reproducing

```sh
python3 kem-34/reproduce_parameters.py
```
