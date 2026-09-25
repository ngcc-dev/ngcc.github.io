<!-- synchronized report: kem-31/report.md -->
Candidate: QIMEN-PIKE
Family: Isogeny-based
Archive: [QIMEN-PIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QIMEN-PIKE.zip) (SHA-256: `eff17fd345bbb44cbaeb822bece3c0b82b8d00f49278e72a89c83e2551c1752a`)

## kem-31-1: Invalid ciphertexts trigger an assertion during decapsulation

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Submitted compressed reference implementation, NGCC-1/2/3
Discovery: Trivial
Exploitation: Unauthenticated decapsulation request aborts the process; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

With an honestly generated key, the all-zero ciphertext aborts decapsulation in every submitted QIMEN-PIKE parameter set. The failing assertion is `is_point_equal(PnQ, P)` in `point_ratio` (`src/ec/ref/ecx/biextension.c:185`), reached while decoding attacker-controlled ciphertext data. The existing mutation sweep also records aborts for fixed-length bit flips. All three reference KAT sets pass, so the failure is specific to malformed input rather than routine operation.

An application that decapsulates untrusted ciphertexts in-process can therefore be terminated by a single request. This is a confirmed availability failure in the submitted assertion-enabled build, not evidence of key recovery or a failure of the underlying isogeny assumption. Disabling assertions has not been established as a safe repair: malformed points must be checked and rejected explicitly before use.

### Reproducing

```sh
make -C security
make -C kem-31 libs
security/ngcc_security kem-31/lib/libNGCC-1.so kem-zero
security/ngcc_security kem-31/lib/libNGCC-2.so kem-zero
security/ngcc_security kem-31/lib/libNGCC-3.so kem-zero
```

Run each separately because it aborts the process. All three reproduced locally; `make -C kem-31 test` passed all three honest-input KAT sets.

## kem-31-2: Non-canonical field encodings make ciphertexts malleable without changing the key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: NGCC-1, NGCC-2, and NGCC-3 reference implementations
Discovery: Moderate
Exploitation: One decapsulation query on a byte-distinct copy of the challenge ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

`fp_decode` reduces field elements modulo `p` without rejecting values at least `p`, and NGCC-1 also leaves 4 bytes of each 64-byte field slot unread. Decapsulation compares and hashes the re-encoded decoded ciphertext rather than the received bytes (`KEM_AlgorithmInstance.c:245,252`). Replacing any field element `x` by `x + p`, or changing an unread slot byte, therefore returns the honest key. The submission claims IND-CCA security, which is trivially violated.

### Reproducing

```sh
python3 kem-31/reproduce_ciphertext_alias.py
```

## kem-31-3: Malformed public keys hang or abort encapsulation

Severity: Medium
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
