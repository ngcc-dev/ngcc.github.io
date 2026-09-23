<!-- synchronized report: kem-31/report.md -->
Candidate: QIMEN-PIKE
Family: Isogeny-based
Archive: [QIMEN-PIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QIMEN-PIKE.zip)

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
