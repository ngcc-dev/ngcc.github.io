<!-- synchronized report: kem-19/report.md -->
Candidate: Lore
Family: Lattice (module-LWR)
Archive: [Lore.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Lore.zip) (SHA-256: `e33130fb45a3b1e220f8043739d1396a884c0043cb4336104e67e5404c7cc725`)

## kem-19-1: Lore-512's reducible ring admits smaller quotient attacks

Severity: Medium
Status: Lead
Layer: Design
Affected: Lore-512 (Lore-L4), both SHAKE and SM3 variants
Discovery: Moderate
Exploitation: Forum's heuristic full-recovery estimate is about 2^451 classical work; not independently validated
Credit: Xu Haomeng and collaborators
Date: 2026-09-23
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/US6X74OOCAN377LPXHUOJBHR7BSOQ3EB/)

Lore-512 uses `Z_1028[x]/(x^768+1)`, where `1028 = t·q` with the specification's headline modulus `q = 257` and `t = 4`. Here `x^768+1 = (x^256+1)(x^512-x^256+1)`. The factors are coprime modulo 1028: writing `y=x^256`, their Bézout difference is `3`, which is invertible modulo 1028. Public ring equations therefore project into degree-256 and degree-512 quotient rings, and the two recovered secret projections would reconstruct the full secret by CRT. A secret with coefficients in `{-2,-1,0,1,2}` projects to coefficients bounded by 6 and 4 respectively, so the smaller instances do not lose the small-secret structure.

The forum estimates approximately 451 classical and 391 quantum bits for full recovery, below the claimed 512-bit classical level. Those figures depend on an independent-coefficient/GSA lattice model that has **not** been reproduced here and does not fully model Lore's fixed-composition secret, rounding correlations, or concrete reduction costs. This is a structurally verified parameter-selection lead, not a demonstrated full-size key recovery or a confirmed 451-bit attack.

### Reproducing

```sh
python3 kem-19/reproduce_ring_projection.py
```

The preflight checks exact quotient multiplication and CRT reconstruction modulo 1028 using small-secret polynomials. It does not run lattice reduction; inspect `Lore-L4/params.h` and `poly.c` in the official archive's `Lore-SHAKE` or `Lore-SM3` reference backend for the modulus, degree, and negacyclic multiplication. These sources are not needed to run the preflight.
