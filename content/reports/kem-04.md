<!-- synchronized report: kem-04/report.md -->
Candidate: BAG-Piglet
Family: Code-based (rank metric)
Archive: [BAG-Piglet.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BAG-Piglet.zip) (SHA-256: `31afe1f2f4e97ad77929d7855c7d9011d69755049d155c09be9339bc99b1d405`)

## kem-04-1: Secret-dependent pivoting in the Gabidulin decoder

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all four parameter sets
Discovery: Moderate
Exploitation: Local control-flow/cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The decapsulator expands the private PKE key and decrypts a chosen ciphertext. The resulting word combines ciphertext with private `x` (`src/scheme/bag_piglet.c:325-378`). The augmented-Gabidulin decoder calls `gabidulin_code_decode_3`; its discrepancy-dependent loop chooses a pivot index and branches on discrepancy values (`src/common/gabidulin.c:273-390`). The branchless final KEM fallback selection does not hide that earlier secret-dependent control flow and memory access. No inversion from observed pivots to private `x` has been shown, so this is not rated a full key-recovery or remote attack.

Constant-time fix (moderate, hence Medium): the pivot search loop, data-dependent swaps and update branches must be replaced by a fixed-iteration decoder with masked pivot selection and swaps. That technique is published (Bettaieb, Bidoux, Gaborit and Marcatel, PQCrypto 2019) and has moderate cost, so this is a substantial rewrite without a significant performance loss.

### Reproducing

The source-level witness is the chain `src/common/ccakem.c:125-132` → `src/scheme/bag_piglet.c:325-378` → `src/common/augabidulin.c:120-133` → `src/common/gabidulin.c:273-390` under `Implementations/Reference_Implementation/bag_piglet128/`. See `constant_time.md` for the secret/public classification and scope.

## kem-04-2: The rejection key does not bind the received ciphertext

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All BAG-Piglet parameter sets; key recovery executed for BAG-Piglet-128 and -256
Discovery: Non-trivial
Exploitation: Recovery of the decryption secret `x` and of honest challenge keys from 57,057 (BAG-Piglet-128) and 353,557–392,779 (BAG-Piglet-256, two runs) decapsulation queries; about 2^19 and 2^26 queries estimated for -384 and -512, not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Algorithm 2 (§1.4) specifies `K(ξ, ct')` on rejection, where `ct'` is the re-encryption of the decrypted message rather than the received ciphertext; `ccakem_decaps` follows it. Distinct invalid ciphertexts that decrypt to the same message therefore share a rejection key, exposing a plaintext-checking oracle when keys are observable. This departs from standard Fujisaki–Okamoto rejection, so the stated IND-CCA2 proof does not establish the submitted construction's claim.

The oracle recovers the decryption secret `x`. The attacker records the rejection key of one ciphertext that decrypts to a fixed nonzero `m0`; a later decapsulation returns that key exactly when its ciphertext also decrypts to `m0`. Probe ciphertexts with `u = (u1, 0)` place a chosen subspace in the suffix that the augmented-Gabidulin decoder annihilates (`augabidulin.c:70–133`) and a known number of extra error dimensions in the prefix, so decoding succeeds exactly when that subspace meets the support of `x·u1` plus a known offset. Taking `u1 = 1` tests `Supp(x)`; taking `u1 = h1` with offset `s1` tests `Supp(y1)`. With both supports known, `s1 = x·h1 + y1` is an overdetermined linear system over F2 whose unique solution is `x`, which decrypts any honest ciphertext to its key `K*`.

Reclassified from High to Critical on 2026-10-31 after recovery of `x` and the challenge key. The separate implicit-rejection seed is not recovered. At BAG-Piglet-384 and -512 the reference decoder accepts errors beyond its textbook radius, so the probes were not calibrated there; the query counts for those sets are estimates.

### Reproducing

```sh
python3 kem-04/reproduce_rejection_key.py kem-04/lib/libbag_piglet_128.so
sh kem-04/reproduce_key_recovery.sh     # NGCC_LONG=1 adds BAG-Piglet-256
```

The second script builds `kem-04/reproduce_key_recovery.c` against the unmodified reference sources. The attack uses only the public key and `ccakem_decaps` outputs; the secret key is read only by the final validation line. BAG-Piglet-128 takes about five minutes; BAG-Piglet-256 takes about an hour.

## kem-04-3: Removing one error block puts maximal-minors key recovery below the BAG-Piglet-128 target

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BAG-Piglet-128 parameters; BAG-Piglet-256 is within about 2 bits of its target by an unvalidated estimate and is not claimed
Discovery: Non-trivial
Exploitation: Estimated classical key-recovery cost of 2^118.4, or 2^114.6 with the reported refinement, against a 128-bit target; no attack executed
Credit: Tianrui Wang, Anyu Wang, Yuxuan Li, Qicheng Teng and Bo Pang; cost replay by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-23
Original source: [Wang et al., *Decoding Cost Lens: Cost Estimation for Code-Based Cryptography*, ePrint 2026/2994](https://eprint.iacr.org/2026/2994), §4.4 and Tables 6–7
Follow-up source: [the authors' 2026-11-24 PKC Forum announcement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MJW5ZUNQTBEOZZALFR7ADNALFE23OUYP/); [the BRQC, BRA and C-Multi-UR-AG teams' 2026-11-25 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/75FDLOEPQAYGUJS4KFKKZPTMLJPOSKST/)

The public key is `s = x·h + y` with `h = (h1, h2)`, so the secret `(x, y1, y2)` is three blocks of length `n` and rank 4 under two equations (Equation (1), physical p. 10). Proposition 3.1 (physical p. 19) prices the maximal-minors (MM) attack on this instance with ω = 2.8 (physical p. 16), and Table 5 (physical p. 21) declares 2^148 for BAG-Piglet-128.

The proposition lets the attacker guess coordinates to be zero but not puncture them, and puncturing costs nothing. Guess one coordinate of the first block and five of the third to be zero, with probability 2^-24, and puncture the other 38 coordinates of the third block. The third block is then gone. The remaining two-block system has about 2^33.7 minor variables in place of 2^50.7 and is still overdetermined. Ordinary MM costs 2^118.4 at ω = 2.8 and 2^125.2 at ω = 3.

Wang et al. also give a zero-direction variant (ZD-MM), which leaves the last zero unguessed and tests every direction in one block against a kernel that is computed once. It costs 2^114.6 here.

For BAG-Piglet-256 ordinary MM costs 2^261.8, above target. The paper's ZD-MM estimate packs pairs of coordinates over `F_4`, which gives three blocks of length 39 and rank 6 with extension degree 79 (Table 1: `n = 78`, `m = 79`, key weights 6). Six guessed zeros in the first block and contraction of the second give 2^254.0 at the specification's ω = 2.8 (Table 5 declares 2^269); the estimate reaches 2^256 at ω = 2.833. It rests on ZD-MM alone, whose rank assumptions have not been checked on any instance, so BAG-Piglet-256 is not claimed. BAG-Piglet-384 and -512 stay above their targets (2^394.2 and 2^567.6).

The authors' [2026-11-24 PKC Forum announcement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MJW5ZUNQTBEOZZALFR7ADNALFE23OUYP/) lists BAG-Piglet-256 with BAG-Piglet-128 as below target by ZD-MM, and links the estimator's source code at `github.com/ISYRHH/CodeBasedEstimator`, which was not evaluated. BAG-Piglet-256 was listed in this entry from 2026-11-24 on that basis and withdrawn on 2026-11-25. In a [2026-11-25 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/75FDLOEPQAYGUJS4KFKKZPTMLJPOSKST/), the BRQC, BRA and C-Multi-UR-AG teams dispute the ZD-MM model. They say its equation counts do not show that the matrices have the ranks it needs, and that it has not been run on an instance. They also say that the paper's count of independent equations depends on the order of the blocks and is too large. The counts in this entry are the minimum over all block orders, which is the bound the reply describes. At BAG-Piglet-256 the order matters: the paper's listed order gives 2^63.44 equations for 2^63.35 unknowns, and the minimum, 2^63.27, is the one that reproduces 2^254.0. The BAG-Piglet-128 claim does not use ZD-MM. Its system has 2^33.78 equations for 2^33.69 unknowns in either block order, so it is overdetermined, the case the reply accepts.

These are cost estimates in the specification's own model: operation counts without constants, and MM equations assumed independent. No decoding was run.

### Reproducing

```sh
python3 security/rank_mm_costs.py --report-id kem-04-3
```

The witness finds the block-removing guess by its own search and recomputes the paper's ordinary-MM and ZD-MM key-recovery exponents for all four sets to three decimals. The ZD-MM figures are recomputed as the paper models them; that does not validate the model.

## kem-04-4: The coded BAG-Piglet-128 parameters have a 2^-82.2 failure rate, not the claimed 2^-130

Severity: High
Status: Proof gap
Layer: Design
Affected: BAG-Piglet-128 as defined by Table 2 and the submitted reference and optimized implementations; BAG-Piglet-256, -384 and -512 are not affected
Discovery: Moderate
Exploitation: None demonstrated; about 0.2 decryption failures are expected among 2^80 honest ciphertexts, and no failure-based key recovery is shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-23

The specification gives BAG-Piglet-128 two shapes. Table 1 (physical p. 8) lists `n = 47` and `m = 43`. Table 2 on the same page defines the ring by `P(X)` of degree 43 and the field by `f(X)` of degree 47, and `src/scheme/parameters.h:13–18` in both trees has `n = 43`, `m = 47`, `n′ = 43`, `n1 = 2` and `ε = 30`. The sizes are the same either way. The failure rate of physical p. 4 depends on `n` through the length `n·n1 − n′` of the augmented tail. With `δ = 35`, Table 1's `n = 47` gives 2^-130.2, the 2^-130 of Table 5 (physical p. 21). The coded `n = 43` gives 2^-82.2. The other three levels are stated consistently and reproduce Table 5.

The IND-CCA argument (physical p. 14) assumes a failure probability bounded by 2^-λ. At the coded rate, 2^80 decapsulations of honest ciphertexts contain about 0.2 failures, so the Fujisaki–Okamoto bound loses its meaning near the evaluation budget of 2^80 queries. At 2^64 the expected number is 2^-18. No attack that uses failures has been shown. A failure depends on the secret key, but finding one costs about 2^82 decapsulations.

### Reproducing

```sh
python3 kem-04/reproduce_failure_rate.py
```

The script reads the parameters of all four levels from `parameters.h` in both trees and evaluates the specification's failure-rate formula. For BAG-Piglet-128 it also evaluates Table 1's `n = 47` and prints the expected failures at 2^64 and 2^80 ciphertexts. It runs in under a second.
