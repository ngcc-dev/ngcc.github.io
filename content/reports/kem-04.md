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
