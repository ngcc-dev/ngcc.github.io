<!-- synchronized report: kem-31/report.md -->
Candidate: QIMEN-PIKE
Family: Isogeny-based
Archive: [QIMEN-PIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QIMEN-PIKE.zip) (SHA-256: `eff17fd345bbb44cbaeb822bece3c0b82b8d00f49278e72a89c83e2551c1752a`)

## kem-31-1: Invalid ciphertexts trigger an assertion during decapsulation

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted compressed reference implementation, NGCC-1/2/3
Discovery: Trivial
Exploitation: Unauthenticated decapsulation request aborts the process; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; root-cause and memory-safety extension by Jieyu Zheng (GitHub @zhengjieyu)
Date: 2026-09-23
Follow-up source: [Jieyu Zheng's GitHub issue #22, 2026-09-26](https://github.com/ngcc-dev/ngcc-harness/issues/22)

With an honestly generated key, the all-zero ciphertext aborts decapsulation in every submitted QIMEN-PIKE parameter set. The failing assertion is `is_point_equal(PnQ, P)` in `point_ratio` (`src/ec/ref/ecx/biextension.c:185`), reached while decoding attacker-controlled ciphertext data. The existing mutation sweep also records aborts for fixed-length bit flips. All three reference KAT sets pass, so the failure is specific to malformed input rather than routine operation.

An application that decapsulates untrusted ciphertexts in-process can therefore be terminated by a single request. This is a confirmed availability failure in the submitted assertion-enabled build, not evidence of key recovery or a failure of the underlying isogeny assumption. Disabling assertions has not been established as a safe repair: malformed points must be checked and rejected explicitly before use.

Jieyu Zheng identified a concrete memory-safety root cause behind this warning. `ct_decode` decodes four attacker-controlled hint fields as signed `int` values (`pike_compressed.c:1049,1122-1128`). The reconstruction routines test only `hint < 20` before evaluating `Z_NQR_TABLE[hint]` or `NQR_TABLE[hint]` (`basis.c:1725-1727,1834-1836`), so a negative hint reads before either 20-element table. Changing any one hint of an honest ciphertext to `-1` aborted all 12 tested parameter-set/field combinations; the issue's AddressSanitizer run additionally records a 128-byte out-of-bounds read. This confirms that removing assertions is unsafe. The demonstrated consequence remains process termination: no read data is returned, and no disclosure, key recovery, or control-flow effect has been shown. Under the classification policy this remains Low and keeps its existing ID.

### Reproducing

```sh
make -C security
make -C kem-31 libs
security/ngcc_security kem-31/lib/libNGCC-1.so kem-zero
security/ngcc_security kem-31/lib/libNGCC-2.so kem-zero
security/ngcc_security kem-31/lib/libNGCC-3.so kem-zero
```

Run each separately because it aborts the process. All three reproduced locally; `make -C kem-31 test` passed all three honest-input KAT sets.

The controlled negative-hint witness preserves every other byte of an honest ciphertext and checks an honest-decapsulation control:

```sh
make -C kem-31 reproduce-hint
```

## kem-31-2: Non-canonical field encodings make ciphertexts malleable without changing the key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: NGCC-1, NGCC-2, and NGCC-3 reference implementations
Discovery: Moderate
Exploitation: One decapsulation query on a byte-distinct copy of the challenge ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §5](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

`fp_decode` reduces field elements modulo `p` without rejecting values at least `p`, and NGCC-1 also leaves 4 bytes of each 64-byte field slot unread. Decapsulation compares and hashes the re-encoded decoded ciphertext rather than the received bytes (`KEM_AlgorithmInstance.c:245,252`). Replacing any field element `x` by `x + p`, or changing an unread slot byte, therefore returns the honest key. The submission claims IND-CCA security, which is trivially violated.

The specification's Algorithm 15 (§3.3.2, p. 36) compares the received `ct` with the re-encryption `ct′` and uses `Hct(ct)` to derive the key. Section 3.3.1 says this hash binds the full ciphertext transcript. Appendix B.1 (p. 78) describes reduced field-element serialization, while Chapter 5 notes that NGCC-1 reserves 64 bytes for a field element that needs only 60. The specification does not define a parser for malformed byte encodings. In the submitted byte API, `ct_decode` accepts them, and `compare_ct_for_kdf` and `derive_ss_from_m_and_ct` use a fresh encoding of the decoded object (`KEM_AlgorithmInstance.c:612–633,588–605`). This normalization is where the byte-distinct alias survives the specified equality and hash steps.

### Reproducing

```sh
python3 kem-31/reproduce_ciphertext_alias.py
```

## kem-31-3: Malformed public keys hang or abort encapsulation

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: NGCC-1, NGCC-2, and NGCC-3 reference implementations
Discovery: Trivial
Exploitation: A sender encapsulating to a crafted public key with square A+2 in F_{p²} loops or aborts
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Encapsulation does not validate the public key. With the two basis hints set to zero, `ec_curve_to_basis_Tmin_from_hint` loops when `A+2` is a square in `F_{p²}` (`ec/ref/pike_ecx/basis.c:1283–1307`), a condition an attacker can choose. With the curve coefficient of NGCC-1 set to zero, encapsulation aborts on an assertion (`ec/ref/ecx/biextension.c:1448`). Honest encapsulation takes well under two seconds.

### Reproducing

```sh
python3 kem-31/reproduce_malformed_public_key.py
```

## kem-31-4: A shared torsion mask leaks a square-coset constraint on the secret degree

Severity: Medium
Status: Confirmed
Layer: Design
Affected: QIMEN-PIKE NGCC-1, NGCC-2, and NGCC-3
Discovery: Non-trivial
Exploitation: Public pairing leakage removes about two bits from the secret-degree candidate space; no oracle, key recovery, or below-target attack is established
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HKC2JLEC7CWIQHGV22RUQDIFSPI55LZT/)

Additional references: [POKÉ, ePrint 2024/624, §6.1](https://eprint.iacr.org/2024/624), and [Moriya's POKÉ weak-key analysis, ePrint 2026/1002](https://eprint.iacr.org/2026/1002)

Algorithm 9 and Equation (8.1) publish the C-torsion points `R_A=[gamma]phi(R_0)` and `S_A=[gamma]phi(S_0)` using the same scalar. On the `C1` component, Weil-pairing compatibility directly exposes

```text
e_C(R_A,S_A) = e_C(R_0,S_0)^(deg(phi) * gamma^2).
```

Because `C` is smooth, the exponent can be extracted publicly by Pohlig–Hellman. Since `gamma^2` is a square, it constrains `deg(phi)` to one quadratic-residuosity coset. The `C2` component gives the same square-coset condition after the public points are normalized onto the specified twist; it is not justified by the displayed `C1` pairing alone. This contradicts §8.3.1, which says that the critical degree information is hidden by “independent masking scalars with uniformly distributed determinants” and cannot be recovered through pairings. The compressed reference and optimized sources likewise sample one `gamma` and combine it into both basis scalars (`pike_compressed.c:163,174–175`).

The forum analysis validates the pairing invariant on all 30 KATs and demonstrates the completion algebra on reduced two-dimensional instances. Exact factor counting gives filter strengths of 1.96, 1.89, and 2.88 bits for NGCC-1/2/3; the post prints 1.88 for NGCC-3. This is a small, confirmed public leak.

The post's below-target figures come from its baseline candidate accounting, not from this filter alone. No formal eight-dimensional theta-chain recovery was run, and charging the reported approximately `2^36` field operations needed to complete each surviving candidate closes the few-bit margin. With no query oracle that amplifies the leak and no demonstrated recovery consequence, the square-coset constraint is Medium and Confirmed rather than a High recovery lead.

### Reproducing

```sh
python3 kem-31/reproduce_pairing_constraint.py
```

The local witness checks Algorithm 9, the contradictory §8.3.1 sentence, and the shared-mask data flow in both submitted source trees. It then exhaustively demonstrates on a small composite modulus that a common mask confines the public exponent to one square coset, whereas independent masks cover the full unit group. It does not reproduce the 30-vector pairing calculation or a formal-parameter key recovery.
