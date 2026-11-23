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

## kem-31-5: The Lucas ladder branches on every bit of a secret exponent

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: NGCC-1, -2 and -3; reference and optimized implementations
Discovery: Trivial
Exploitation: Local branch trace of the encryption exponent, from which the message mask follows, and of the long-term decryption exponent; not measured, no recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
`lucas_sequence` evaluates a Lucas ladder with `if (bit == 1) { … } else { … }` for each exponent bit (`src/gf/ref/gfx/fp2.c:332–357`). Both arms cost one multiplication and one squaring, so total time is flat, but the branch taken and the operands touched follow the bit.

Encryption calls it with the exponent `t1·t2 mod D` on a public pairing value and masks the message with a hash of the result (`pike_compressed.c:796`). That exponent is the per-ciphertext secret: a branch trace of one encapsulation, or of the re-encryption inside decapsulation, gives it, and the mask, the message and the shared secret follow. Decryption calls the same function with an exponent derived from the long-term secret isogeny data (`:1005`). The specification states that the field layer "runs in constant time on all secret-dependent inputs" (p. 81).

The code was not instrumented or timed for this entry.

Constant-time fix (easy, hence Low): compute both updates and select with the conditional swap the field layer already provides.

### Reproducing

```sh
sed -n '332,357p' kem-31/Implementations/Implementations/src/gf/ref/gfx/fp2.c
grep -rn 'lucas_sequence(' kem-31/Implementations/Implementations/src/pike/ref/pikex_compressed/pike_compressed.c
```

This is a source witness.

## kem-31-6: Optimized key generation writes one element past the isogeny degree array

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Optimized implementation, NGCC-1, NGCC-2 and NGCC-3; the reference implementation is not affected
Discovery: Trivial
Exploitation: None shown; a fixed two-byte zero write into structure padding in every key generation, independent of any input, with keys, ciphertexts and shared secrets unchanged
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-23
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A4FNTSCHPPZZFJGKEZT3DDCKX4SAABTO/)

In the optimized tree, `TORSION_ODD_PRIMEPOWERS` has four entries at every level, the last equal to 1 (`src/precomp/ref/NGCC_{1,2,3}/torsion_constants.c:18,39,60`). `ec_degree_odd_t` is `uint16_t[P_LEN + M_LEN]`, three elements (`src/ec/ref/include/ec.h:105`). `id2iso_ideal_to_kernel_dlogs_odd` zeroes one degree per table entry (`src/id2iso/ref/id2isox/id2iso.c:158–161`), so every key generation executes `(*deg)[3] = 0`. The reference tree's table has three entries. The optimized tree's generator lacks the `[:-1]` that trims the list in the reference tree (`scripts/precompute_torsion_constants.sage:58`).

The array is the last member of `ec_isog_odd_t`, and the only caller passes the `degree` member of key generation's stack object (`id2iso.c:262`, `pike_compressed.c:93,193`). The two bytes therefore fall in the structure's tail padding (bytes 1038–1039 of 1040 at NGCC-1), which nothing reads. The fourth iteration has no other effect because the gcd with 1 is 1. Built with the tree's Release flags under GCC 15.2, the optimized tree reproduces the official KATs at all three levels. `-fsanitize=bounds` reports the write; AddressSanitizer does not.

The tree's own check at `id2iso.c:268` asserts that the two sizes are equal. The optimized tree therefore aborts in every key generation unless assertions are compiled out, as its documented Release build does.

### Reproducing

```sh
sh kem-31/reproduce_torsion_oob.sh
```

The witness checks the dimensions in both trees, then builds each level of each tree in a temporary directory with `-fsanitize=bounds`; the reference tree is the control. It needs x86-64 with BMI2 and ADX, GCC and GMP, and takes about 15 seconds.

## kem-31-7: Every key generation and decapsulation leaks a theta-chain array

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: NGCC-1, NGCC-2 and NGCC-3; reference and optimized implementations
Discovery: Trivial
Exploitation: Unbounded memory growth in a long-running process; each decapsulation query, accepted or implicitly rejected, adds 0.7–7.7 MB; no disclosure or corruption
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool, noted the leak; sites and measurement by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-23
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A4FNTSCHPPZZFJGKEZT3DDCKX4SAABTO/)

`theta_chain_comput_strategy` allocates the steps of each dimension-two isogeny chain with `out->steps = malloc((n - 1) * sizeof(theta_isogeny_t))` (`src/hd/ref/hdx/theta_isogenies.c:1472`; optimized tree `:1486`), and neither tree frees it. Key generation computes two chains (`pike_compressed.c:215,253`), decryption one (`:968`) and encryption none. The array has a fixed size: 736,488 bytes at NGCC-1, 1,930,584 at NGCC-2 and 7,665,000 at NGCC-3.

With `malloc` and `free` wrapped, each `kem_keygen` left two more arrays live, each `kem_dec` one and each `kem_enc` none, at every level. Over 20 calls of each at NGCC-1 the growth was exactly linear. Decapsulation decrypts before its re-encryption check, so an implicitly rejected ciphertext leaks the same array. Key generation also leaks one GMP integer of about 100–330 bytes (`tmp` in `endomorphism_application_even_basis`, `id2iso.c:67`).

Fix: free `hd_isog.steps` before the second chain and at the end of `keygen` and `decrypt`.

### Reproducing

```sh
sh kem-31/reproduce_keygen_leak.sh
```

The witness builds each level of the reference tree with the uniform build's flags and no sanitizer, wraps `malloc` and `free` at link time, and counts live blocks after two calls of each operation and one decapsulation of a ciphertext with a flipped byte. A build with the fix leaves nothing live. It also runs the optimized tree at NGCC-1 and takes about 30 seconds.
