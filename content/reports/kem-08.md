<!-- synchronized report: kem-08/report.md -->
Candidate: BW-KEM
Family: Lattice-based KEM
Archive: [BW-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BW-KEM.zip)

## kem-08-1: C128 decapsulation branches on decrypted coefficients

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: BW_KEM_C128 reference implementation
Discovery: Trivial
Exploitation: Secret-dependent branch trace before ciphertext validation; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Decapsulation computes `mp = v - sᵀu` from the recipient secret and chosen ciphertext (`indcpa.c:321-331`), then branches on the sign of each centered coefficient while converting it to a message (`poly.c:174-193`). GCC `-O2` retains a conditional `jns`; the FO comparison occurs later (`kem.c:155-170`). The function is identical to the AFS-KEX C128 path in `kex-02-2`. This establishes secret-dependent control flow, not a measured remote oracle or a transferable KyberSlash key-recovery attack; see `constant_time.md`.

### Reproducing

```sh
ref=kem-08/Implementations/Reference_Implementation/BW_KEM_C128
cc -O2 -std=c99 -DBWKEM128_INTERNAL_COMPAT -DBWKEM128_USE_ICCS_AUXFUNC \
  -I"$ref" -Iapi -S "$ref/poly.c" -o - |
  sed -n '/bwkem128_poly_tomsg:/,/\.size[[:space:]]*bwkem128_poly_tomsg/p' |
  grep -E '\bjns\b'
```

The source trace and compiled branch are reproducible; no timing-based extraction is claimed.
