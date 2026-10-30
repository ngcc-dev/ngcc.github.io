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

### Follow-up Analysis

The Lore team's [first response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KGBWR5YQU6ASUKNVUQEBNNJZ7TWZIOY4/) and [revised-parameter post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/W6XIOQDXGIUZPVKR3MZW4HZCDJEVYRMR/) concern a revised parameter set. This report continues to describe the archived Round 1 submission identified above and does not apply its factorization claim to a later set.

### Proposed fixes

The Lore team's [revised-parameter post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/W6XIOQDXGIUZPVKR3MZW4HZCDJEVYRMR/) proposes changing Lore-512 to `n=1024`, `k=2`, and `x^1024+1`, while retaining `q=257` and `t=4`, together with revised fixed-composition and BCH parameters. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-19/reproduce_ring_projection.py
```

The preflight checks exact quotient multiplication and CRT reconstruction modulo 1028 using small-secret polynomials. It does not run lattice reduction; inspect `Lore-L4/params.h` and `poly.c` in the official archive's `Lore-SHAKE` or `Lore-SM3` reference backend for the modulus, degree, and negacyclic multiplication. These sources are not needed to run the preflight.

## kem-19-2: Lore-384 and -512 emit 256-bit keys from 256-bit keygen seeds

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Lore-L3 and Lore-L4 SHAKE and SM3 reference, AVX and NEON implementations
Discovery: Trivial
Exploitation: The 32-byte shared secret directly misses the 384- and 512-bit NGCC output-length targets; offline public-key seed search costs at most 2^256 trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

The submitted §3.5 (physical p. 22) openly uses 256-bit SHAKE/SM3 constructions as *temporary references* for the 384- and 512-bit sets. All twelve higher-level source trees fix `LORE_SYMBYTES=32` for hashes, seeds and shared secrets (for example `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/params.h:18`); encapsulation outputs only that many bytes (the same tree's `kem.c:118–139`, with matching paths in the other trees). The NGCC Submission Requirements §2(2) require the encapsulated key to be at least as long as its security level. Thus both submitted high-level KEM outputs miss a direct call requirement, independent of the lattice estimates.

There is also an offline secret-key ceiling. `crypto_kem_keypair_derand` passes only the first 32 bytes of its 64-byte coins to `indcpa_keypair_derand` (that tree's `kem.c:61–71`); the second half is rejection state. The PKE key generator expands that first half deterministically into the secret and public key (`indcpa.c:363–378`). Enumerating at most `2^256` first-half values and comparing generated public keys recovers a decapsulation secret for a target key. This is a concrete bound, not a completed `2^256` computation. The spec's disclosure of the temporary 256-bit instantiation is noted, but does not change the frozen candidate's targets.

### Reproducing

```sh
python3 kem-19/reproduce_seed_ceiling.py
```

The certificate checks the twelve affected source trees and both independent 256-bit ceilings; it does not run the exhaustive search.

## kem-19-3: BCH decoding timing leaks Lore secret coefficients

Severity: High
Status: Probable
Layer: Implementation
Affected: Lore-L2 SM3 reference implementation (reported full secret recovery); Lore-L3/L4 and AVX/NEON variants have the same data-dependent decoder paths by source inspection. Lore-L1 is excluded.
Discovery: Moderate
Exploitation: The reporter claims complete recovery of the 1024-coefficient Lore-L2 secret using about 2,200–2,940 decapsulation timing queries on STM32F4; recovery has not been independently reproduced here.
Credit: Jinnuo Li, with AI assistance
Date: 2026-10-30
Original source: [Jinnuo Li's PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/EURSTLNLPYYJ3VV7JGJA5MAHNCKQMMKH/)

The [PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/EURSTLNLPYYJ3VV7JGJA5MAHNCKQMMKH/) describes three timing signals in the submitted BCH decoder. `compute_syndromes` branches on each decoded received-word bit and conditionally performs `2t` syndrome updates (`bch_codec.c:403–418`); Berlekamp–Massey returns early when its degree exceeds `t` (`:476–478`); and the locator search terminates after finding the required roots (`:511–519`). `decode_bch` also exits early for zero syndromes (`:544–554`). The word being decoded is derived from the secret-dependent decryption result (`poly.c:563–578`), and the decoder runs within decapsulation (`kem.c:198`). The reported measurements attribute roughly 13,208, 305,780, and 31,704 clock cycles to the three respective signals.

The post reports complete recovery of all 1,024 secret coefficients on an STM32F4 using the unmodified Lore-L2 SM3 reference implementation, with 2,936.5, 2,212.5, and 2,218 average queries for its three attacks. It also reports complete recovery on ten x86-host keys using the second signal. These results are not independently reproduced in this report, so the status is Probable. The source-level secret-dependent paths are present in the frozen code; no dependence on the ICCS placeholder hash/XOF is part of this timing mechanism. Other levels and optimized implementations are included only by source inspection, not by measured end-to-end recovery.

### Proposed fixes

The reporter recommends implementing the syndrome, error-location, and correction steps in constant time across the affected versions. This recommendation is recorded without evaluation; the forum post does not provide a measured constant-time replacement or a Lore team response.

### Reproducing

Inspect the cited `bch_codec.c`, `poly.c`, and `kem.c` paths in the archived Lore-L2 SM3 reference source. This confirms the secret-dependent control flow and its decapsulation call path, but does not reproduce the timing deltas or the reported key recovery. The [original forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/EURSTLNLPYYJ3VV7JGJA5MAHNCKQMMKH/) gives the platforms, query counts, and measured timing differences; it includes no reproducer or trace data.
