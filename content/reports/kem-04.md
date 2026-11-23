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
Affected: BAG-Piglet-128 parameters; BAG-Piglet-256 is within about 2 bits of its target and is not claimed
Discovery: Non-trivial
Exploitation: Estimated classical key-recovery cost of 2^118.4, or 2^114.6 with the reported refinement, against a 128-bit target; no attack executed
Credit: Tianrui Wang, Anyu Wang, Yuxuan Li, Qicheng Teng and Bo Pang; cost replay by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-23
Original source: [Wang et al., *Decoding Cost Lens: Cost Estimation for Code-Based Cryptography*, ePrint 2026/2994](https://eprint.iacr.org/2026/2994), §4.4 and Tables 6–7

The public key is `s = x·h + y` with `h = (h1, h2)`, so the secret `(x, y1, y2)` is three blocks of length `n` and rank 4 under two equations (Equation (1), physical p. 10). Proposition 3.1 (physical p. 19) prices the maximal-minors (MM) attack on this instance with ω = 2.8 (physical p. 16), and Table 5 (physical p. 21) declares 2^148 for BAG-Piglet-128.

The proposition lets the attacker guess coordinates to be zero but not puncture them, and puncturing costs nothing. Guess one coordinate of the first block and five of the third to be zero, with probability 2^-24, and puncture the other 38 coordinates of the third block. The third block is then gone. The remaining two-block system has about 2^33.7 minor variables in place of 2^50.7 and is still overdetermined. Ordinary MM costs 2^118.4 at ω = 2.8 and 2^125.2 at ω = 3.

Wang et al. also give a zero-direction variant (ZD-MM), which leaves the last zero unguessed and tests every direction in one block against a kernel that is computed once. It costs 2^114.6 here. For BAG-Piglet-256 their ZD-MM estimate is 2^254.0, after rewriting the instance over `F_4`, while ordinary MM costs 2^261.8; that margin is too small to claim. BAG-Piglet-384 and -512 stay above their targets (2^394.2 and 2^567.6).

These are cost estimates in the specification's own model: operation counts without constants, and MM equations assumed independent. No decoding was run.

### Reproducing

```sh
python3 security/rank_mm_costs.py --report-id kem-04-3
```

The witness finds the block-removing guess by its own search and recomputes the paper's ordinary-MM and ZD-MM key-recovery exponents for all four sets to three decimals.

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
